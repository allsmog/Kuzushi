//! Reading git's NUL-framed (`-z`) path output.
//!
//! Git's human-readable path output quotes any name holding a byte it must not
//! emit literally — a double quote, a backslash, a control character, or (with
//! the default `core.quotePath`) any byte above ASCII — so `src/café.rs` is
//! printed as `"src/caf\303\251.rs"`, and a newline inside a name survives as
//! an escape rather than as a line break. A reader that splits that output on
//! `\n` and keeps the text verbatim is holding the name of a file that does
//! not exist.
//!
//! Git's name-listing commands take `-z`, which prints the raw bytes of each
//! name followed by NUL and quotes nothing. Asking for `-z` is the cheaper
//! half of the problem: it removes the quoting instead of decoding it.
//! [`crate::git_quoted_path`] is for the names that only exist inside diff
//! text, where the quoting is part of the format and `-z` does not reach.

use anyhow::{Context, Result};

/// The path records in one NUL-framed git stdout.
///
/// `label` names the caller in both error messages, because a failure here is
/// reported to an operator who is running a scan, not reading this module.
///
/// A name this process cannot spell is an error rather than a lossy
/// replacement: a path with U+FFFD in it names a different file than the one
/// git reported, and silently scanning the wrong file is the defect this
/// module exists to prevent.
pub(crate) fn nul_separated_paths(stdout: &[u8], label: &str) -> Result<Vec<String>> {
    anyhow::ensure!(
        stdout.is_empty() || stdout.last() == Some(&0),
        "{label}: git path output is not NUL-framed"
    );
    let text = std::str::from_utf8(stdout)
        .with_context(|| format!("{label}: a git path is not valid UTF-8"))?;
    Ok(text
        .split('\0')
        .filter(|record| !record.is_empty())
        .map(str::to_owned)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_every_record_without_touching_its_bytes() {
        assert_eq!(
            nul_separated_paths(
                "src/café.rs\0src/my file.rs\0src/a\nb.rs\0 lead.rs\0".as_bytes(),
                "test"
            )
            .unwrap(),
            vec![
                "src/café.rs".to_string(),
                "src/my file.rs".to_string(),
                "src/a\nb.rs".to_string(),
                " lead.rs".to_string(),
            ]
        );
    }

    #[test]
    fn empty_output_is_no_paths() {
        assert!(nul_separated_paths(b"", "test").unwrap().is_empty());
    }

    #[test]
    fn unframed_output_is_an_error() {
        let error = nul_separated_paths(b"src/a.rs", "test")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("not NUL-framed"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn non_utf8_name_is_an_error_rather_than_a_replacement() {
        let error = nul_separated_paths(b"src/\xffbad.rs\0", "test")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("not valid UTF-8"),
            "unexpected error: {error}"
        );
    }
}
