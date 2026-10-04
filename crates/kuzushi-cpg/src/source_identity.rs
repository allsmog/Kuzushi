//! Content identity for the exact source snapshot consumed by the frontend.
use super::{build_excludes, extensions_for, load_project};
use cpg_incremental::Project;
use std::io::{Read, Write};
use std::path::Path;

pub(super) struct SourceCensus {
    pub(super) sources: Vec<(String, String)>,
    pub(super) identity: String,
}

pub(super) fn source_census(root: &Path, lang: &str) -> Result<SourceCensus, String> {
    let excludes = build_excludes(lang);
    let sources = cpg_cli::collect_sources_filtered(root, extensions_for(lang), &excludes)?;
    let canonical = root.canonicalize().map_err(|error| error.to_string())?;
    let mut digest = blake3::Hasher::new();
    hash_part(&mut digest, b"kuzushi-cpg-snapshot-v1");
    hash_part(&mut digest, canonical.as_os_str().as_encoded_bytes());
    hash_part(&mut digest, lang.as_bytes());
    hash_part(&mut digest, include_bytes!("../../../Cargo.lock"));
    for exclude in excludes {
        hash_part(&mut digest, exclude.as_bytes());
    }
    for (path, source) in &sources {
        hash_part(&mut digest, path.as_bytes());
        hash_part(&mut digest, source.as_bytes());
    }
    Ok(SourceCensus {
        sources,
        identity: digest.finalize().to_hex().to_string(),
    })
}

fn hash_part(digest: &mut blake3::Hasher, bytes: &[u8]) {
    digest.update(&(bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

pub(super) fn load_fresh(census: &SourceCensus, lang: &str, path: &Path) -> Option<Project> {
    let manifest = std::fs::read_to_string(path.with_extension("identity")).ok()?;
    let expected = format!("{}\n{}\n", census.identity, file_digest(path).ok()?);
    if manifest != expected {
        return None;
    }
    load_project(path, lang)
}

pub(super) fn save_project(project: &Project, path: &Path, identity: &str) -> Result<(), String> {
    save_artifact(project, path, identity)
        .map_err(|error| format!("cannot save {}: {error}", path.display()))
}

fn save_artifact(project: &Project, path: &Path, identity: &str) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("graph has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let graph = tempfile::NamedTempFile::new_in(parent)?;
    project
        .cpg
        .save(&graph.path().to_string_lossy())
        .map_err(std::io::Error::other)?;
    graph.as_file().sync_all()?;
    let digest = file_digest(graph.path())?;
    graph.persist(path)?;
    let mut manifest = tempfile::NamedTempFile::new_in(parent)?;
    writeln!(manifest, "{identity}\n{digest}")?;
    manifest.as_file().sync_all()?;
    manifest.persist(path.with_extension("identity"))?;
    Ok(())
}

fn file_digest(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok(digest.finalize().to_hex().to_string());
        }
        digest.update(&buffer[..count]);
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::ensure_project;

    #[test]
    fn deletion_rename_and_manifest_damage_invalidate_cached_graphs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.go"), "package main\nfunc keep() {}\n").unwrap();
        std::fs::write(
            dir.path().join("old.go"),
            "package main\nfunc remove() {}\n",
        )
        .unwrap();
        let (_, first) = ensure_project(dir.path(), "go").unwrap();
        std::fs::remove_file(dir.path().join("old.go")).unwrap();
        let (_, deleted) = ensure_project(dir.path(), "go").unwrap();
        assert!(!deleted.reused_cache);
        assert!(deleted.methods < first.methods);
        std::fs::rename(dir.path().join("main.go"), dir.path().join("renamed.go")).unwrap();
        assert!(!ensure_project(dir.path(), "go").unwrap().1.reused_cache);
        std::fs::write(first.cpg_path.with_extension("identity"), "incomplete").unwrap();
        assert!(!ensure_project(dir.path(), "go").unwrap().1.reused_cache);
        assert!(ensure_project(dir.path(), "go").unwrap().1.reused_cache);
    }

    #[test]
    fn changing_sources_after_the_snapshot_does_not_change_what_is_built() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("main.go");
        std::fs::write(&path, "package main\nfunc original() {}\n").unwrap();
        let census = super::source_census(dir.path(), "go").unwrap();
        std::fs::write(&path, "package main\nfunc replacement() {}\n").unwrap();
        assert!(census.sources[0].1.contains("original"));
        assert_ne!(
            census.identity,
            super::source_census(dir.path(), "go").unwrap().identity
        );
    }
}
