//! Which scan engines are reproducible enough to retire findings.
//!
//! Shared by the re-scan reconciler (which marks vanished findings stale) and
//! the scan-to-scan comparison (which reports a finding resolved). Both must
//! agree, or a comparison could claim `resolved` for a finding the reconciler
//! would refuse to retire.

/// Reproducible static scanners whose absence in a same-scope re-run is honest
/// evidence a finding is gone. Deliberately a whitelist: an unlisted (possibly
/// agentic or new) tool is treated as non-deterministic and never retires a
/// finding — a missed `Fixed` is acceptable, a fabricated one is not.
const DETERMINISTIC_SCANNERS: &[&str] = &[
    "semgrep",
    "codeql",
    "dep-hygiene",
    "secret-scan",
    "cargo-audit",
    "license-scan",
    "sbom-scan",
    "iac-scan",
];

pub(crate) fn is_deterministic_scanner(tool: &str) -> bool {
    DETERMINISTIC_SCANNERS.contains(&tool)
}

/// The individual engines behind a finding's `tool`. Deduplication merges the
/// tools of coalesced observations into one comma-joined string, so a stored
/// tool may name several engines (`"codeql,semgrep"`).
pub(crate) fn tool_components(tool: &str) -> impl Iterator<Item = &str> {
    tool.split(',')
        .map(str::trim)
        .filter(|component| !component.is_empty())
}

/// Whether every engine behind `tool` is deterministic. A merged tool is only
/// as retirable as its weakest component: one agentic engine in the merge means
/// absence is never proof. A tool naming no engine at all proves nothing.
pub(crate) fn all_components_deterministic(tool: &str) -> bool {
    let mut named_any = false;
    tool_components(tool).all(|component| {
        named_any = true;
        is_deterministic_scanner(component)
    }) && named_any
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agentic_and_unknown_engines_are_never_deterministic() {
        for tool in ["taint-iris", "agentic-sast", "carlini-threat-hunt", "brand-new-tool", ""] {
            assert!(!is_deterministic_scanner(tool), "{tool} must not retire findings");
        }
    }

    #[test]
    fn reproducible_static_scanners_are_deterministic() {
        for tool in ["semgrep", "codeql", "secret-scan"] {
            assert!(is_deterministic_scanner(tool));
        }
    }

    #[test]
    fn merged_tools_are_deterministic_only_when_every_component_is() {
        assert!(all_components_deterministic("codeql, semgrep"));
        assert!(!all_components_deterministic("semgrep,taint-iris"));
        assert_eq!(
            tool_components("codeql, semgrep").collect::<Vec<_>>(),
            vec!["codeql", "semgrep"]
        );
    }

    #[test]
    fn empty_and_whitespace_tool_strings_are_never_deterministic() {
        for tool in ["", "  ", ",", " , "] {
            assert!(
                !all_components_deterministic(tool),
                "{tool:?} names no engine, so absence is not proof"
            );
        }
        assert!(
            all_components_deterministic("semgrep,"),
            "a trailing separator does not invent a second engine"
        );
        assert!(all_components_deterministic("semgrep"));
    }
}
