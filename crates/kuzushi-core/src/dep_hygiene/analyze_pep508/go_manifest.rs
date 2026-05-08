use super::*;

pub(in crate::dep_hygiene) fn analyze_go_mod(
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
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
