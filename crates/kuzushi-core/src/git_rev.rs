//! Validation for git revision arguments that reach `git` positionally.
//!
//! `git` parses any argument beginning with `-` as an option, so a revision
//! taken from tool input or external advisory data (`diffBase`, `since
//! <ref>`, harvested fix commits) must never start with `-`: `git diff
//! --output=<path>...` turns a "revision" into an arbitrary-path file write.
//! Real revisions never need a leading dash — git itself refuses ref names
//! that start with `-` (git-check-ref-format).

use anyhow::Result;

pub(crate) fn ensure_safe_git_rev(rev: &str, context: &str) -> Result<()> {
    anyhow::ensure!(!rev.trim().is_empty(), "{context}: git revision is empty");
    anyhow::ensure!(
        !rev.starts_with('-'),
        "{context}: git revision {rev:?} must not start with '-' \
         (it would be parsed as a git option)"
    );
    anyhow::ensure!(
        !rev.chars().any(|c| matches!(c, '\0' | '\n' | '\r')),
        "{context}: git revision {rev:?} contains control characters"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_revision_shapes() {
        for rev in [
            "HEAD",
            "HEAD~3",
            "main",
            "origin/release/1.2",
            "v1.0.0^{}",
            "abc1234",
            "feature_branch@{yesterday}",
        ] {
            assert!(ensure_safe_git_rev(rev, "test").is_ok(), "{rev}");
        }
    }

    #[test]
    fn rejects_option_shaped_and_malformed_revisions() {
        for rev in ["", "  ", "-x", "--output=/tmp/pwn", "-O/tmp/pwn", "a\nb", "a\0b"] {
            assert!(ensure_safe_git_rev(rev, "test").is_err(), "{rev:?}");
        }
    }
}
