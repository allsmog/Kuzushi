use super::prelude::*;
use super::*;

pub(super) fn analyze_pep508(file_path: &Path, spec: &str) -> Option<DepHygieneFinding> {
    let cleaned = spec.split(';').next().unwrap_or_default().trim();
    let name_len = cleaned
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
        .map(char::len_utf8)
        .sum::<usize>();
    if name_len == 0 {
        return None;
    }
    let name = &cleaned[..name_len];
    let constraint = cleaned[name_len..].trim();

    if constraint.is_empty() {
        return Some(DepHygieneFinding::new(
            ManifestKind::PyprojectToml,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            "PEP 508: unconstrained - accepts any installed version, including malicious",
        ));
    }

    if is_floor_only_nonempty_range(constraint) {
        return Some(DepHygieneFinding::new(
            ManifestKind::PyprojectToml,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::Medium,
            "PEP 508: floor-only - declare an upper bound for supply-chain hygiene",
        ));
    }

    None
}

pub(super) fn analyze_cargo_toml(file_path: &Path, raw: &str) -> Vec<DepHygieneFinding> {
    let mut out = Vec::new();
    let mut in_deps = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed == "[dependencies]" || trimmed == "[dev-dependencies]";
            continue;
        }
        if !in_deps || trimmed.is_empty() {
            continue;
        }

        let Some((name, value)) = split_assignment(trimmed) else {
            continue;
        };
        if value.starts_with('{') {
            continue;
        }
        let constraint = clean_quoted_constraint(value);
        if constraint == "*" || constraint.is_empty() {
            out.push(DepHygieneFinding::new(
                ManifestKind::CargoToml,
                file_path,
                name,
                constraint,
                DepHygieneSeverity::High,
                "Cargo: wildcard pin - accepts any future release without review",
            ));
        } else if is_floor_only_number_range(&constraint) {
            out.push(DepHygieneFinding::new(
                ManifestKind::CargoToml,
                file_path,
                name,
                constraint,
                DepHygieneSeverity::Medium,
                "Cargo: floor-only range; declare an upper bound to fix the supply-chain surface",
            ));
        }
    }

    out
}

pub(super) fn analyze_go_mod(file_path: &Path, raw: &str) -> Vec<DepHygieneFinding> {
    let mut out = Vec::new();
    let mut in_require_block = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("require") && trimmed.ends_with('(') {
            in_require_block = true;
            continue;
        }
        if in_require_block && trimmed == ")" {
            in_require_block = false;
            continue;
        }

        let candidate = if in_require_block {
            trimmed
        } else {
            trimmed.strip_prefix("require ").unwrap_or_default().trim()
        };
        if candidate.is_empty() {
            continue;
        }

        let without_comment = candidate
            .split("//")
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        if without_comment.is_empty() {
            continue;
        }

        let tokens = without_comment.split_whitespace().collect::<Vec<_>>();
        if tokens.len() < 2 {
            continue;
        }
        let name = tokens[0];
        let version = tokens[1];

        if is_go_pseudo_version(version) {
            out.push(DepHygieneFinding::new(
                ManifestKind::GoMod,
                file_path,
                name,
                version,
                DepHygieneSeverity::Medium,
                "go.mod: pinned to a pseudo-version (commit hash); tag a release for an immutable pin",
            ));
        } else if version == "latest" || version == "v0.0.0" {
            out.push(DepHygieneFinding::new(
                ManifestKind::GoMod,
                file_path,
                name,
                version,
                DepHygieneSeverity::High,
                "go.mod: floating latest / v0.0.0 - supply chain unstable",
            ));
        }
    }

    out
}

pub(super) fn canonical_directory(target: &Path) -> Result<PathBuf> {
    if !target.exists() {
        anyhow::bail!("dep-hygiene: target does not exist: {}", target.display());
    }
    let canonical = fs::canonicalize(target)
        .with_context(|| format!("dep-hygiene: failed to resolve {}", target.display()))?;
    if !canonical.is_dir() {
        anyhow::bail!(
            "dep-hygiene: target is not a directory: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

pub(super) fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=')?;
    if eq == 0 {
        return None;
    }
    Some((line[..eq].trim(), line[eq + 1..].trim()))
}

pub(super) fn quoted_list_entry(line: &str) -> Option<&str> {
    let body = line.strip_prefix('"')?;
    let body = body.strip_suffix(',').unwrap_or(body).trim_end();
    body.strip_suffix('"')
}

pub(super) fn clean_quoted_constraint(value: &str) -> String {
    let mut value = value.trim();
    value = value.strip_suffix(',').unwrap_or(value).trim_end();
    value = value.strip_prefix('"').unwrap_or(value);
    value = value.strip_suffix('"').unwrap_or(value);
    value.trim().to_string()
}

pub(super) fn is_floor_only_number_range(value: &str) -> bool {
    if value.contains('<') || value.contains(',') {
        return false;
    }
    let Some(rest) = value.strip_prefix('>') else {
        return false;
    };
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    rest.chars().next().is_some_and(|ch| ch.is_ascii_digit())
}

pub(super) fn is_floor_only_nonempty_range(value: &str) -> bool {
    if value.contains('<') || value.contains(',') || value.split_whitespace().count() != 1 {
        return false;
    }
    is_floor_only_number_range(value)
}

pub(super) fn is_go_pseudo_version(version: &str) -> bool {
    let Some(rest) = version.strip_prefix("v0.0.0-") else {
        return false;
    };
    let Some((timestamp, hash)) = rest.split_once('-') else {
        return false;
    };
    timestamp.len() == 14
        && timestamp.chars().all(|ch| ch.is_ascii_digit())
        && hash.len() == 12
        && hash.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub(super) fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}
