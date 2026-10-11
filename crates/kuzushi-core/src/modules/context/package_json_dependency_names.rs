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
