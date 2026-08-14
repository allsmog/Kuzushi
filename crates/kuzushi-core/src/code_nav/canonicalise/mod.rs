//! Path canonicalisation guard for code-nav tools.
//!
//! The model can ask any tool with arbitrary input. We must reject paths
//! that escape the configured workspace root (e.g. `..`, absolute paths
//! pointing outside, symlinks aimed at `/etc`). The caller passes the
//! intended root and a candidate path; this returns either a canonical
//! path inside the root or a structured error.

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum CanonicaliseError {
    #[error("path is empty")]
    Empty,
    #[error("path could not be canonicalised: {0}")]
    Resolve(String),
    #[error("path escapes workspace root: {path}")]
    Escape { path: String },
    #[error("workspace root could not be canonicalised: {0}")]
    BadRoot(String),
}

/// Resolve `candidate` to a canonical path inside `root`. Both relative
/// (`src/foo.rs`) and absolute (`/abs/path/inside/root/foo.rs`) inputs are
/// accepted as long as the resolved path lives under `root`.
///
/// Symlinks are resolved by `Path::canonicalize` — if a symlink points
/// outside the root, the canonicalised target is checked, so the guard
/// holds even when an attacker plants a symlink in the workspace.
pub fn canonicalise_within(root: &Path, candidate: &str) -> Result<PathBuf, CanonicaliseError> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return Err(CanonicaliseError::Empty);
    }

    let canonical_root = root
        .canonicalize()
        .map_err(|e| CanonicaliseError::BadRoot(e.kind().to_string()))?;

    let mut joined = PathBuf::from(trimmed);
    if joined.is_relative() {
        joined = canonical_root.join(joined);
    }

    let canonical = match joined.canonicalize() {
        Ok(path) => path,
        Err(error) => {
            // Normal "file does not exist" — return a typed error rather
            // than leaking the absolute filesystem path back to the model.
            return Err(CanonicaliseError::Resolve(error.kind().to_string()));
        }
    };

    if !canonical.starts_with(&canonical_root) {
        return Err(CanonicaliseError::Escape {
            path: trimmed.to_string(),
        });
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn symlink_file(source: &Path, destination: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(source, destination)
    }

    #[cfg(windows)]
    fn symlink_file(source: &Path, destination: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(source, destination)
    }

    #[test]
    fn relative_path_resolves_inside_root() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("foo.rs"), "fn main() {}").unwrap();
        let path = canonicalise_within(root, "foo.rs").unwrap();
        assert!(path.ends_with("foo.rs"));
    }

    #[test]
    fn absolute_path_outside_root_is_rejected() {
        let tmp = tempdir().unwrap();
        // /etc/passwd typically exists; pick a path we know is outside the
        // tempdir.
        let err = canonicalise_within(tmp.path(), "/etc/passwd").unwrap_err();
        assert!(matches!(err, CanonicaliseError::Escape { .. }), "{err:?}");
    }

    #[test]
    fn dotdot_escape_is_rejected() {
        let tmp = tempdir().unwrap();
        // Create /tmp/<rand>/inner; root = /tmp/<rand>/inner.
        let inner = tmp.path().join("inner");
        fs::create_dir_all(&inner).unwrap();
        fs::write(tmp.path().join("outside.txt"), "secret").unwrap();
        let err = canonicalise_within(&inner, "../outside.txt").unwrap_err();
        assert!(matches!(err, CanonicaliseError::Escape { .. }), "{err:?}");
    }

    #[test]
    fn missing_file_returns_resolve_error() {
        let tmp = tempdir().unwrap();
        let err = canonicalise_within(tmp.path(), "nonexistent.rs").unwrap_err();
        assert!(matches!(err, CanonicaliseError::Resolve(_)), "{err:?}");
    }

    #[test]
    fn empty_path_is_rejected() {
        let tmp = tempdir().unwrap();
        let err = canonicalise_within(tmp.path(), "  ").unwrap_err();
        assert!(matches!(err, CanonicaliseError::Empty));
    }

    #[test]
    fn symlink_to_outside_is_caught_post_canonicalise() {
        // Skip on platforms that can't make symlinks in the test env.
        let tmp = tempdir().unwrap();
        let outside_dir = tempdir().unwrap();
        let outside_file = outside_dir.path().join("secret.txt");
        fs::write(&outside_file, "private").unwrap();

        let inside = tmp.path().join("link.txt");
        if symlink_file(&outside_file, &inside).is_err() {
            return;
        }

        let err = canonicalise_within(tmp.path(), "link.txt").unwrap_err();
        // Symlinks to outside the root produce Escape after canonicalize().
        assert!(matches!(err, CanonicaliseError::Escape { .. }), "{err:?}");
    }
}
