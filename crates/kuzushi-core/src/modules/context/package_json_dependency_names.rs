use super::*;

const MAX_CONTEXT_WALK_ENTRIES: usize = 100_000;

pub(in crate::modules) fn package_json_dependency_names(parsed: &Value) -> BTreeSet<&str> {
    let mut deps = BTreeSet::new();
    for key in ["dependencies", "devDependencies", "peerDependencies"] {
        if let Some(object) = parsed.get(key).and_then(Value::as_object) {
            deps.extend(object.keys().map(|key| key.as_str()));
        }
    }
    deps
}

pub(in crate::modules) fn insert_package_json_context_signals(
    deps: &BTreeSet<&str>,
    frameworks: &mut BTreeSet<&'static str>,
    auth_patterns: &mut BTreeSet<&'static str>,
    orm_or_db: &mut BTreeSet<&'static str>,
    sanitization_libs: &mut BTreeSet<&'static str>,
) {
    insert_dependency_signals(
        deps,
        frameworks,
        &[
            ("express", "express"),
            ("next", "next"),
            ("react", "react"),
            ("@nestjs/core", "nestjs"),
        ],
    );
    insert_any_dependency_signal(
        deps,
        auth_patterns,
        &["passport", "next-auth", "@auth/core"],
        "session/auth middleware",
    );
    insert_any_dependency_signal(deps, auth_patterns, &["jsonwebtoken", "jose"], "jwt");
    insert_any_dependency_signal(deps, orm_or_db, &["prisma", "@prisma/client"], "prisma");
    insert_dependency_signals(
        deps,
        orm_or_db,
        &[("mongoose", "mongoose"), ("sequelize", "sequelize")],
    );
    insert_dependency_signals(deps, sanitization_libs, &[("zod", "zod"), ("joi", "joi")]);
}

fn insert_dependency_signals(
    deps: &BTreeSet<&str>,
    target: &mut BTreeSet<&'static str>,
    mappings: &[(&str, &'static str)],
) {
    for (dependency, signal) in mappings {
        if deps.contains(dependency) {
            target.insert(signal);
        }
    }
}

fn insert_any_dependency_signal(
    deps: &BTreeSet<&str>,
    target: &mut BTreeSet<&'static str>,
    dependencies: &[&str],
    signal: &'static str,
) {
    if dependencies
        .iter()
        .any(|dependency| deps.contains(dependency))
    {
        target.insert(signal);
    }
}

pub(in crate::modules) fn inspect_manifest_text(
    path: &Path,
    probes: &[&'static str],
    matches: &mut BTreeSet<&'static str>,
) -> Result<()> {
    let mapped = probes
        .iter()
        .map(|probe| (*probe, *probe))
        .collect::<Vec<_>>();
    inspect_manifest_signals(path, &mapped, matches)
}

pub(in crate::modules) fn inspect_manifest_signals(
    path: &Path,
    probes: &[(&str, &'static str)],
    matches: &mut BTreeSet<&'static str>,
) -> Result<()> {
    let Some(raw) = read_optional_manifest(path)? else {
        return Ok(());
    };
    let lower = raw.to_lowercase();
    for (needle, signal) in probes {
        if lower.contains(needle) {
            matches.insert(signal);
        }
    }
    Ok(())
}

pub(in crate::modules) fn read_optional_manifest(path: &Path) -> Result<Option<String>> {
    match crate::bounded_file::read_utf8_text(path, 8 * 1024 * 1024) {
        Ok(raw) => Ok(Some(raw)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("Could not read manifest {}", path.display())),
    }
}

pub(in crate::modules) fn collect_context_files(
    root: &Path,
    dir: &Path,
    sample_limit: usize,
    files_indexed: &mut usize,
    files_sample: &mut Vec<String>,
) -> Result<()> {
    collect_context_files_with_limit(
        root,
        dir,
        sample_limit,
        files_indexed,
        files_sample,
        MAX_CONTEXT_WALK_ENTRIES,
    )
}

fn collect_context_files_with_limit(
    root: &Path,
    dir: &Path,
    sample_limit: usize,
    files_indexed: &mut usize,
    files_sample: &mut Vec<String>,
    entry_limit: usize,
) -> Result<()> {
    let mut entries_seen = 0usize;
    collect_context_files_inner(
        root,
        dir,
        sample_limit,
        files_indexed,
        files_sample,
        &mut entries_seen,
        entry_limit,
    )
}

fn collect_context_files_inner(
    root: &Path,
    dir: &Path,
    sample_limit: usize,
    files_indexed: &mut usize,
    files_sample: &mut Vec<String>,
    entries_seen: &mut usize,
    entry_limit: usize,
) -> Result<()> {
    let read_dir = fs::read_dir(dir)
        .with_context(|| format!("Could not read context directory {}", dir.display()))?;
    let remaining = entry_limit.saturating_sub(*entries_seen);
    let mut entries = read_dir
        .take(remaining.saturating_add(1))
        .collect::<std::io::Result<Vec<_>>>()?;
    anyhow::ensure!(
        entries.len() <= remaining,
        "Context inventory exceeded the {entry_limit}-entry coverage limit"
    );
    *entries_seen += entries.len();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        collect_context_entry(
            root,
            entry,
            sample_limit,
            files_indexed,
            files_sample,
            entries_seen,
            entry_limit,
        )?;
    }

    Ok(())
}

fn collect_context_entry(
    root: &Path,
    entry: fs::DirEntry,
    sample_limit: usize,
    files_indexed: &mut usize,
    files_sample: &mut Vec<String>,
    entries_seen: &mut usize,
    entry_limit: usize,
) -> Result<()> {
    if should_skip_path(&entry.file_name().to_string_lossy()) {
        return Ok(());
    }
    let file_type = entry.file_type()?;
    let path = entry.path();
    if file_type.is_dir() {
        return collect_context_files_inner(
            root,
            &path,
            sample_limit,
            files_indexed,
            files_sample,
            entries_seen,
            entry_limit,
        );
    }
    if file_type.is_file() {
        collect_context_file(root, &path, sample_limit, files_indexed, files_sample);
    }
    Ok(())
}

#[cfg(test)]
mod context_walk_limit_tests {
    use super::*;

    #[test]
    fn context_walk_errors_instead_of_silently_truncating() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        fs::write(temp.path().join("b.rs"), "fn b() {}\n").unwrap();
        let mut indexed = 0;
        let mut sample = Vec::new();

        let error = collect_context_files_with_limit(
            temp.path(),
            temp.path(),
            1,
            &mut indexed,
            &mut sample,
            1,
        )
        .unwrap_err();

        assert!(error.to_string().contains("coverage limit"));
    }
}

fn collect_context_file(
    root: &Path,
    path: &Path,
    sample_limit: usize,
    files_indexed: &mut usize,
    files_sample: &mut Vec<String>,
) {
    *files_indexed += 1;
    if files_sample.len() >= sample_limit {
        return;
    }
    let display_path = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();
    files_sample.push(display_path);
}
