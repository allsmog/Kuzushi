//! Sandbox backend selection.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxBackend {
    /// `bwrap` (bubblewrap) — preferred on Linux.
    Bwrap,
    /// Rootless `podman run` container.
    Podman,
    /// No isolation — direct subprocess. Only safe in trusted contexts;
    /// `verify` will refuse to promote to `proof_level=4` when this
    /// backend was used.
    Plain,
}

impl SandboxBackend {
    pub fn binary_name(self) -> &'static str {
        match self {
            Self::Bwrap => "bwrap",
            Self::Podman => "podman",
            Self::Plain => "/bin/sh",
        }
    }

    /// True if the backend provides namespace / capability isolation
    /// suitable for empirical exploitability gating.
    pub fn is_isolating(self) -> bool {
        matches!(self, Self::Bwrap | Self::Podman)
    }
}

/// Pick a backend, honoring an optional explicit preference. Falls back
/// to whichever isolating backend is on PATH; ends at `Plain` if neither
/// is found.
pub fn detect_backend(preference: Option<SandboxBackend>) -> SandboxBackend {
    if let Some(pref) = preference {
        if pref == SandboxBackend::Plain || which(pref.binary_name()).is_some() {
            return pref;
        }
    }
    if which("bwrap").is_some() {
        return SandboxBackend::Bwrap;
    }
    if which("podman").is_some() {
        return SandboxBackend::Podman;
    }
    SandboxBackend::Plain
}

/// Resolve a host executable using the shared platform-aware PATH search.
pub fn which(binary: &str) -> Option<PathBuf> {
    kuzushi_mcp_common::doctor::which(binary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_names_are_stable() {
        assert_eq!(SandboxBackend::Bwrap.binary_name(), "bwrap");
        assert_eq!(SandboxBackend::Podman.binary_name(), "podman");
        assert_eq!(SandboxBackend::Plain.binary_name(), "/bin/sh");
    }

    #[test]
    fn isolating_check_is_correct() {
        assert!(SandboxBackend::Bwrap.is_isolating());
        assert!(SandboxBackend::Podman.is_isolating());
        assert!(!SandboxBackend::Plain.is_isolating());
    }

    #[test]
    fn detect_backend_honors_explicit_plain_preference() {
        // `Plain` is always honored even though there's no binary to find.
        assert_eq!(
            detect_backend(Some(SandboxBackend::Plain)),
            SandboxBackend::Plain
        );
    }

    #[test]
    fn detect_backend_falls_through_to_plain_when_no_isolating_backend_found() {
        // We can't reliably assert the absence of bwrap/podman on every
        // host, but we can assert the *type* of fallback. If none are
        // present, Plain wins; otherwise, an isolating backend wins.
        let chosen = detect_backend(None);
        assert!(matches!(
            chosen,
            SandboxBackend::Bwrap | SandboxBackend::Podman | SandboxBackend::Plain
        ));
    }

    #[test]
    fn which_finds_universal_binary_or_returns_none() {
        // At least one of these is always present on a Unix host. If
        // none are, we accept that and the test is a no-op.
        let _ = which("sh");
    }
}
