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

/// `true` when two reported paths name the same source file.
///
/// Reported paths reach Kuzushi against different roots. A scanner run against
/// `app/` reports `src/main.rs`, while `git diff --name-only` on the enclosing
/// repository reports `app/src/main.rs`, so a caller that has to decide "is
/// this the file?" accepts one path being a trailing part of the other.
///
/// The trailing part has to begin at a separator. `str::ends_with` alone does
/// not require that, and the two call sites that used it answered yes for files
/// that merely share a name ending: `src/notauth.rs` ends with `auth.rs`, so a
/// finding in a file neither side ever named was claimed as that file.
///
/// `/` is the only separator read here, for the same reason
/// [`normalize_reported_source_path`] keeps `a\b.rs` literal: `\` is an
/// ordinary filename byte on Unix and detectors preserve it verbatim, so
/// splitting on it would equate two different files. Paths are otherwise
/// compared byte for byte — a reported path is literal data, and surrounding
/// whitespace belongs to the filename.
pub(crate) fn reported_paths_name_same_file(left: &str, right: &str) -> bool {
    if left.is_empty() || right.is_empty() {
        return false;
    }
    left == right || ends_at_segment_boundary(left, right) || ends_at_segment_boundary(right, left)
}

/// `true` when `whole` ends with `tail` and the byte before `tail` is `/`, so
/// `tail` covers whole path segments rather than the end of a longer name.
fn ends_at_segment_boundary(whole: &str, tail: &str) -> bool {
    let Some(prefix_len) = whole.len().checked_sub(tail.len()) else {
        return false;
    };
    prefix_len > 0 && whole.as_bytes()[prefix_len - 1] == b'/' && whole.ends_with(tail)
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

    #[test]
    fn same_file_accepts_a_differing_root_and_rejects_a_shared_name_ending() {
        // One path relative to the scan target, the other to the repository.
        assert!(reported_paths_name_same_file(
            "src/main.rs",
            "app/src/main.rs"
        ));
        assert!(reported_paths_name_same_file(
            "app/src/main.rs",
            "src/main.rs"
        ));
        assert!(reported_paths_name_same_file("src/x.rs", "src/x.rs"));

        // Distinct files whose names merely end alike.
        assert!(!reported_paths_name_same_file("src/notauth.rs", "auth.rs"));
        assert!(!reported_paths_name_same_file("auth.rs", "src/notauth.rs"));
        assert!(!reported_paths_name_same_file(
            "crates/core/tests.rs",
            "s.rs"
        ));
        assert!(!reported_paths_name_same_file("api/v2/handler.rs", "v2"));
    }

    #[test]
    fn same_file_keeps_path_bytes_literal_and_names_no_file_for_an_empty_path() {
        // `\` is a filename byte, not a separator: these are two files.
        assert!(!reported_paths_name_same_file("src\\main.rs", "main.rs"));
        assert!(!reported_paths_name_same_file(" main.rs", "main.rs"));
        assert!(!reported_paths_name_same_file("src/Main.rs", "main.rs"));

        assert!(!reported_paths_name_same_file("", ""));
        assert!(!reported_paths_name_same_file("", "src/main.rs"));
        assert!(!reported_paths_name_same_file("src/main.rs", ""));
    }
}
