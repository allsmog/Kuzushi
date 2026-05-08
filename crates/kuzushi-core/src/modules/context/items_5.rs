use super::prelude::*;
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
    if deps.contains("express") {
        frameworks.insert("express");
    }
    if deps.contains("next") {
        frameworks.insert("next");
    }
    if deps.contains("react") {
        frameworks.insert("react");
    }
    if deps.contains("@nestjs/core") {
        frameworks.insert("nestjs");
    }
    if deps.contains("passport") || deps.contains("next-auth") || deps.contains("@auth/core") {
        auth_patterns.insert("session/auth middleware");
    }
    if deps.contains("jsonwebtoken") || deps.contains("jose") {
        auth_patterns.insert("jwt");
    }
    if deps.contains("prisma") || deps.contains("@prisma/client") {
        orm_or_db.insert("prisma");
    }
    if deps.contains("mongoose") {
        orm_or_db.insert("mongoose");
    }
    if deps.contains("sequelize") {
        orm_or_db.insert("sequelize");
    }
    if deps.contains("zod") {
        sanitization_libs.insert("zod");
    }
    if deps.contains("joi") {
        sanitization_libs.insert("joi");
    }
}

pub(in crate::modules) fn inspect_manifest_text(
    path: &Path,
    probes: &[&'static str],
    matches: &mut BTreeSet<&'static str>,
) -> Result<()> {
    let Ok(raw) = fs::read_to_string(path) else {
        return Ok(());
    };
    let lower = raw.to_lowercase();
    for needle in probes {
        if lower.contains(needle) {
            matches.insert(needle);
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
        let path = entry.path();
        let file_name = entry.file_name();
        if should_skip_path(&file_name.to_string_lossy()) {
            continue;
        }

        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_context_files(root, &path, sample_limit, files_indexed, files_sample)?;
        } else if file_type.is_file() {
            *files_indexed += 1;
            if files_sample.len() < sample_limit {
                let display_path = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                files_sample.push(display_path);
            }
        }
    }

    Ok(())
}
