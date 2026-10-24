use std::path::Path;

/// Reported paths are literal data. Only remove a matching absolute target root.
pub(crate) fn normalize_reported_source_path(path: String, target: &Path) -> String {
    let candidate = Path::new(&path);
    if candidate.is_absolute() {
        return candidate
            .strip_prefix(target)
            .unwrap_or(candidate)
            .display()
            .to_string();
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_paths_keep_relative_bytes_and_only_strip_a_containing_root() {
        let root = tempfile::tempdir().unwrap();
        for value in [
            " leading.rs",
            "trailing.rs ",
            "Case.rs",
            "case.rs",
            "a\\b.rs",
            "a:b.rs",
        ] {
            assert_eq!(
                normalize_reported_source_path(value.into(), root.path()),
                value
            );
        }
        let absolute = root.path().join(" literal 東京.rs ");
        assert_eq!(
            normalize_reported_source_path(absolute.display().to_string(), root.path()),
            " literal 東京.rs "
        );
        let outside = root
            .path()
            .with_extension("sibling")
            .join("owned.rs")
            .display()
            .to_string();
        assert_eq!(
            normalize_reported_source_path(outside.clone(), root.path()),
            outside
        );
    }
}
