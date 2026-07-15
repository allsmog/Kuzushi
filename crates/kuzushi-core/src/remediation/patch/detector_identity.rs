/// Match one canonical `<module>:<verb>` descriptor against either that exact
/// descriptor or the module-only identity stored on findings.
///
/// Prefix matching is deliberately forbidden: `secret` must never match
/// `secret-scan:scan`, and a qualified identity must match its verb exactly.
pub(crate) fn qualified_tool_matches_identity(descriptor: &str, identity: &str) -> bool {
    if matches!((descriptor, identity), ("agentic-sast:scan", "agentic")) {
        return true;
    }
    let Some((module, verb)) = descriptor.split_once(':') else {
        return false;
    };
    if module.is_empty() || verb.is_empty() {
        return false;
    }
    if identity.contains(':') {
        descriptor == identity
    } else {
        module == identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_findings_match_their_exact_qualified_detector() {
        for (descriptor, identity) in [
            ("secret-scan:scan", "secret-scan"),
            ("iac-scan:scan", "iac-scan"),
            ("systems-hunt:systems-hunt", "systems-hunt"),
            // Historical Agentic SAST findings store the task id rather than
            // the descriptor module id. Keep this one explicit alias exact.
            ("agentic-sast:scan", "agentic"),
        ] {
            assert!(qualified_tool_matches_identity(descriptor, identity));
        }
    }

    #[test]
    fn qualified_and_prefix_mismatches_fail_closed() {
        assert!(!qualified_tool_matches_identity(
            "secret-scan:scan",
            "secret"
        ));
        assert!(!qualified_tool_matches_identity(
            "systems-hunt:deep-semantic-hunt",
            "systems-hunt:systems-hunt"
        ));
        assert!(!qualified_tool_matches_identity(
            "secret-scan",
            "secret-scan"
        ));
    }
}
