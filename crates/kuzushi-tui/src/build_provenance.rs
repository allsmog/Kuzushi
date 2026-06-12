//! Runtime access to the compile-time build provenance embedded by
//! `build.rs`. This is what makes a published npm release binary and a
//! `pnpm dev` working-tree build visibly different: same version string,
//! different `(sha · profile)` suffix.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildProvenance {
    pub version: &'static str,
    pub git_sha: &'static str,
    pub dirty: bool,
    pub profile: &'static str,
}

pub fn build_provenance() -> BuildProvenance {
    BuildProvenance {
        version: env!("CARGO_PKG_VERSION"),
        git_sha: env!("KUZUSHI_BUILD_GIT_SHA"),
        dirty: env!("KUZUSHI_BUILD_GIT_DIRTY") == "1",
        profile: env!("KUZUSHI_BUILD_PROFILE"),
    }
}

/// `/config` summary cell: `0.24.0-alpha.4 · ac5a80f12+dirty · debug`.
pub fn build_summary() -> String {
    let p = build_provenance();
    format_build_summary(p.version, p.git_sha, p.dirty, p.profile)
}

/// `--version` string: `0.24.0-alpha.4 (ac5a80f12+dirty · debug)`.
pub fn build_version() -> String {
    let p = build_provenance();
    format!(
        "{} ({} · {})",
        p.version,
        format_git_cell(p.git_sha, p.dirty),
        p.profile
    )
}

/// `build_version()` interned once — clap's `version` attribute needs a
/// `&'static str` (the `string` feature is off workspace-wide).
pub fn build_version_static() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(build_version).as_str()
}

fn format_build_summary(version: &str, git_sha: &str, dirty: bool, profile: &str) -> String {
    format!(
        "{version} · {} · {profile}",
        format_git_cell(git_sha, dirty)
    )
}

fn format_git_cell(git_sha: &str, dirty: bool) -> String {
    if dirty {
        format!("{git_sha}+dirty")
    } else {
        git_sha.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_marks_dirty_trees() {
        assert_eq!(
            format_build_summary("1.2.3", "abc123def", true, "debug"),
            "1.2.3 · abc123def+dirty · debug"
        );
        assert_eq!(
            format_build_summary("1.2.3", "abc123def", false, "release"),
            "1.2.3 · abc123def · release"
        );
    }

    #[test]
    fn provenance_is_populated_at_compile_time() {
        let p = build_provenance();
        assert!(!p.version.is_empty());
        assert!(!p.git_sha.is_empty());
        assert!(!p.profile.is_empty());
    }
}
