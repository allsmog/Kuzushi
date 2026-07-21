//! Shard-manifest resolution for `kuzushi scan --shard` / `--paths`.
//!
//! A shard is a named, reusable workspace-relative scope declared in
//! `<target>/.kuzushi/shards.toml` (or an explicit `--shard-manifest` file):
//!
//! ```toml
//! [shards.parsers]
//! description = "input parsing subsystems"
//! paths = ["src/codec", "src/formats"]
//! ```
//!
//! The CLI compiles the selected shard into the canonical `sast:scan`
//! `paths` option (plus a `shard` provenance label), so shards are pure
//! shorthand over the shared tool-input boundary — no separate behavior path.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(crate) const SHARD_MANIFEST_RELATIVE_PATH: &str = ".kuzushi/shards.toml";

#[derive(Debug, PartialEq)]
pub(crate) struct ResolvedShard {
    pub(crate) name: String,
    pub(crate) paths: Vec<String>,
}

/// Compile the CLI scope flags into canonical `sast:scan` input keys.
/// `--shard` resolves through the manifest; bare `--paths` passes through.
/// Clap marks the two flags as conflicting, so at most one arm applies.
pub(crate) fn apply_scan_paths_scope(
    input: &mut serde_json::Value,
    target: &Path,
    shard: Option<&str>,
    shard_manifest: Option<&Path>,
    paths: &[String],
) -> Result<()> {
    if let Some(name) = shard {
        let resolved = resolve_shard(target, name, shard_manifest)?;
        insert_scope(input, &resolved.paths, Some(&resolved.name))?;
        return Ok(());
    }
    if !paths.is_empty() {
        insert_scope(input, paths, None)?;
    }
    Ok(())
}

fn insert_scope(
    input: &mut serde_json::Value,
    paths: &[String],
    shard_name: Option<&str>,
) -> Result<()> {
    let object = input
        .as_object_mut()
        .context("scan tool input must be a JSON object")?;
    object.insert("paths".to_string(), serde_json::json!(paths));
    if let Some(name) = shard_name {
        object.insert("shard".to_string(), serde_json::json!(name));
    }
    Ok(())
}

pub(crate) fn resolve_shard(
    target: &Path,
    name: &str,
    manifest_override: Option<&Path>,
) -> Result<ResolvedShard> {
    let manifest_path = shard_manifest_path(target, manifest_override);
    let manifest = load_shard_manifest(&manifest_path)?;
    shard_from_manifest(&manifest, name, &manifest_path)
}

fn shard_manifest_path(target: &Path, manifest_override: Option<&Path>) -> PathBuf {
    manifest_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| target.join(SHARD_MANIFEST_RELATIVE_PATH))
}

fn load_shard_manifest(path: &Path) -> Result<toml::Value> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "shard manifest not found at {} — create it with a `[shards.<name>] paths = [...]` \
             table or pass --shard-manifest <file>",
            path.display()
        )
    })?;
    text.parse::<toml::Value>()
        .with_context(|| format!("shard manifest {} is not valid TOML", path.display()))
}

fn shard_from_manifest(
    manifest: &toml::Value,
    name: &str,
    manifest_path: &Path,
) -> Result<ResolvedShard> {
    let shards = manifest
        .get("shards")
        .and_then(toml::Value::as_table)
        .with_context(|| {
            format!(
                "shard manifest {} has no [shards.<name>] tables",
                manifest_path.display()
            )
        })?;
    let entry = shards.get(name).with_context(|| {
        format!(
            "shard {:?} is not defined in {} — available shards: {}",
            name,
            manifest_path.display(),
            available_shard_names(shards)
        )
    })?;
    let paths = shard_entry_paths(entry, name)?;
    Ok(ResolvedShard {
        name: name.to_string(),
        paths,
    })
}

fn available_shard_names(shards: &toml::value::Table) -> String {
    if shards.is_empty() {
        return "(none)".to_string();
    }
    shards.keys().cloned().collect::<Vec<_>>().join(", ")
}

fn shard_entry_paths(entry: &toml::Value, name: &str) -> Result<Vec<String>> {
    let values = entry
        .get("paths")
        .and_then(toml::Value::as_array)
        .with_context(|| format!("shard {name:?} must declare a `paths` array"))?;
    let paths: Vec<String> = values
        .iter()
        .map(|value| shard_path_string(value, name))
        .collect::<Result<_>>()?;
    anyhow::ensure!(!paths.is_empty(), "shard {name:?} has an empty `paths` array");
    Ok(paths)
}

fn shard_path_string(value: &toml::Value, name: &str) -> Result<String> {
    let path = value
        .as_str()
        .with_context(|| format!("shard {name:?} `paths` entries must be strings"))?
        .trim();
    anyhow::ensure!(
        !path.is_empty(),
        "shard {name:?} has a blank `paths` entry"
    );
    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_manifest(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("shards.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn resolves_named_shard_paths() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = write_manifest(
            temp.path(),
            "[shards.parsers]\ndescription = \"parsing\"\npaths = [\"src/codec\", \"src/formats\"]\n",
        );
        let shard = resolve_shard(temp.path(), "parsers", Some(&manifest)).unwrap();
        assert_eq!(shard.name, "parsers");
        assert_eq!(shard.paths, vec!["src/codec", "src/formats"]);
    }

    #[test]
    fn default_manifest_location_is_kuzushi_state() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
        std::fs::write(
            temp.path().join(SHARD_MANIFEST_RELATIVE_PATH),
            "[shards.core]\npaths = [\"src\"]\n",
        )
        .unwrap();
        let shard = resolve_shard(temp.path(), "core", None).unwrap();
        assert_eq!(shard.paths, vec!["src"]);
    }

    #[test]
    fn unknown_shard_lists_available_names() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = write_manifest(temp.path(), "[shards.alpha]\npaths = [\"a\"]\n");
        let error = resolve_shard(temp.path(), "beta", Some(&manifest))
            .unwrap_err()
            .to_string();
        assert!(error.contains("beta"), "{error}");
        assert!(error.contains("alpha"), "{error}");
    }

    #[test]
    fn missing_manifest_is_actionable() {
        let temp = tempfile::tempdir().unwrap();
        let error = resolve_shard(temp.path(), "any", None).unwrap_err().to_string();
        assert!(error.contains("shards.toml"), "{error}");
        assert!(error.contains("--shard-manifest"), "{error}");
    }

    #[test]
    fn empty_or_blank_paths_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let empty = write_manifest(temp.path(), "[shards.bad]\npaths = []\n");
        assert!(resolve_shard(temp.path(), "bad", Some(&empty)).is_err());
        let blank = write_manifest(temp.path(), "[shards.bad]\npaths = [\" \"]\n");
        assert!(resolve_shard(temp.path(), "bad", Some(&blank)).is_err());
    }

    #[test]
    fn shard_scope_injects_paths_and_provenance_label() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = write_manifest(temp.path(), "[shards.web]\npaths = [\"app\"]\n");
        let mut input = serde_json::json!({"triage": true});
        apply_scan_paths_scope(&mut input, temp.path(), Some("web"), Some(&manifest), &[]).unwrap();
        assert_eq!(input["paths"], serde_json::json!(["app"]));
        assert_eq!(input["shard"], serde_json::json!("web"));
        assert_eq!(input["triage"], serde_json::json!(true));
    }

    #[test]
    fn bare_paths_scope_injects_paths_without_label() {
        let temp = tempfile::tempdir().unwrap();
        let mut input = serde_json::json!({});
        apply_scan_paths_scope(&mut input, temp.path(), None, None, &["src/a".to_string()])
            .unwrap();
        assert_eq!(input["paths"], serde_json::json!(["src/a"]));
        assert!(input.get("shard").is_none());
    }

    #[test]
    fn no_scope_flags_leave_input_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let mut input = serde_json::json!({"mode": "standard"});
        apply_scan_paths_scope(&mut input, temp.path(), None, None, &[]).unwrap();
        assert_eq!(input, serde_json::json!({"mode": "standard"}));
    }
}
