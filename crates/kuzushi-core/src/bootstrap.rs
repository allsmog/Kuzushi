use std::fs;
use std::path::Path;

const CONTEXT_FILE: &str = ".kuzushi/CONTEXT.md";
const LEGACY_INFO_FILE: &str = ".kuzushi/INFO.md";
const SECTION_HEADER: &str = "## Project Context";
const MAX_BYTES: usize = 32_768;

/// Read `.kuzushi/CONTEXT.md` (or legacy `.kuzushi/INFO.md`) under `target_root`
/// and return it formatted as a `## Project Context` section ready to be
/// appended to an agent system prompt. Returns `None` when neither file
/// exists, is unreadable, or is empty after trimming.
///
/// Output is capped at 32 KiB to avoid blowing prompt budgets when an
/// operator drops a large doc into CONTEXT.md.
pub fn load_bootstrap_context(target_root: &Path) -> Option<String> {
    for relative in [CONTEXT_FILE, LEGACY_INFO_FILE] {
        let path = target_root.join(relative);
        let raw = match fs::read_to_string(&path) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let body = if trimmed.len() > MAX_BYTES {
            let mut clipped = trimmed[..MAX_BYTES].to_string();
            clipped.push_str("\n\n[truncated; CONTEXT.md exceeds 32 KiB]");
            clipped
        } else {
            trimmed.to_string()
        };
        return Some(format!("{SECTION_HEADER}\n\n{body}\n"));
    }
    None
}

/// Append the bootstrap context (if any) to `base` separated by a blank line.
/// Useful for system-prompt builders.
pub fn append_bootstrap_context(base: &str, target_root: &Path) -> String {
    match load_bootstrap_context(target_root) {
        Some(section) => {
            if base.trim().is_empty() {
                section
            } else {
                format!("{}\n\n{section}", base.trim_end())
            }
        }
        None => base.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn returns_none_when_no_file_present() {
        let dir = tempdir().unwrap();
        assert!(load_bootstrap_context(dir.path()).is_none());
    }

    #[test]
    fn reads_context_md() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".kuzushi")).unwrap();
        fs::write(
            dir.path().join(".kuzushi/CONTEXT.md"),
            "Auth runs in lambdas.\n",
        )
        .unwrap();
        let section = load_bootstrap_context(dir.path()).unwrap();
        assert!(section.starts_with("## Project Context"));
        assert!(section.contains("Auth runs in lambdas."));
    }

    #[test]
    fn falls_back_to_legacy_info_md() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".kuzushi")).unwrap();
        fs::write(
            dir.path().join(".kuzushi/INFO.md"),
            "Legacy bootstrap notes.",
        )
        .unwrap();
        let section = load_bootstrap_context(dir.path()).unwrap();
        assert!(section.contains("Legacy bootstrap notes."));
    }

    #[test]
    fn prefers_context_md_when_both_exist() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".kuzushi")).unwrap();
        fs::write(dir.path().join(".kuzushi/CONTEXT.md"), "modern\n").unwrap();
        fs::write(dir.path().join(".kuzushi/INFO.md"), "legacy").unwrap();
        let section = load_bootstrap_context(dir.path()).unwrap();
        assert!(section.contains("modern"));
        assert!(!section.contains("legacy"));
    }

    #[test]
    fn skips_blank_files() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".kuzushi")).unwrap();
        fs::write(dir.path().join(".kuzushi/CONTEXT.md"), "  \n\n").unwrap();
        assert!(load_bootstrap_context(dir.path()).is_none());
    }

    #[test]
    fn truncates_oversized_files() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".kuzushi")).unwrap();
        let big = "a".repeat(MAX_BYTES + 100);
        fs::write(dir.path().join(".kuzushi/CONTEXT.md"), &big).unwrap();
        let section = load_bootstrap_context(dir.path()).unwrap();
        assert!(section.contains("[truncated"));
    }

    #[test]
    fn append_preserves_existing_prompt() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".kuzushi")).unwrap();
        fs::write(dir.path().join(".kuzushi/CONTEXT.md"), "facts").unwrap();
        let merged = append_bootstrap_context("You are an agent.\n", dir.path());
        assert!(merged.starts_with("You are an agent."));
        assert!(merged.contains("## Project Context"));
        assert!(merged.contains("facts"));
    }

    #[test]
    fn append_returns_base_when_no_context() {
        let dir = tempdir().unwrap();
        let merged = append_bootstrap_context("base prompt", dir.path());
        assert_eq!(merged, "base prompt");
    }
}
