use super::*;

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
    let Ok(raw) = fs::read_to_string(path) else {
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

pub(in crate::modules) fn collect_context_files(
    root: &Path,
    dir: &Path,
    sample_limit: usize,
    files_indexed: &mut usize,
    files_sample: &mut Vec<String>,
) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        collect_context_entry(root, entry, sample_limit, files_indexed, files_sample)?;
    }

    Ok(())
}

fn collect_context_entry(
    root: &Path,
    entry: fs::DirEntry,
    sample_limit: usize,
    files_indexed: &mut usize,
    files_sample: &mut Vec<String>,
) -> Result<()> {
    if should_skip_path(&entry.file_name().to_string_lossy()) {
        return Ok(());
    }
    let Ok(file_type) = entry.file_type() else {
        return Ok(());
    };
    let path = entry.path();
    if file_type.is_dir() {
        return collect_context_files(root, &path, sample_limit, files_indexed, files_sample);
    }
    if file_type.is_file() {
        collect_context_file(root, &path, sample_limit, files_indexed, files_sample);
    }
    Ok(())
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
