use super::compile_scope_rule::compile_scope_rule;
use super::compile_whitebox_rules::compile_whitebox_rules;
use super::scan_ignore_comments::scan_ignore_comments;
use crate::findings::Finding;
use crate::proof::suppressions::load_whitebox_suppressions;
use crate::suppressions::domain::SuppressionRule;
use crate::suppressions::persistence::load_suppression_rules;
use crate::workspace::{ProgramScope, WorkspaceTarget};
use anyhow::Result;

/// Every suppression rule source funneled into one set (Grype's uniform
/// pipeline), plus malformed in-source comment diagnostics.
pub struct EffectiveRules {
    pub rules: Vec<SuppressionRule>,
    pub malformed_comments: Vec<String>,
}

/// Assemble all rule sources for a workspace. Comment-derived rules are
/// recomputed per call — the source code is their store, so deleting a comment
/// removes the rule with no staleness machinery.
pub fn effective_suppression_rules(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
    scope: Option<&ProgramScope>,
) -> Result<EffectiveRules> {
    let mut rules = load_suppression_rules(workspace)?;
    rules.extend(compile_whitebox_rules(&load_whitebox_suppressions(workspace)?));
    if let Some(scope) = scope {
        rules.extend(compile_scope_rule(scope));
    }
    let comment_scan = scan_ignore_comments(workspace.root(), findings);
    rules.extend(comment_scan.rules);
    Ok(EffectiveRules {
        rules,
        malformed_comments: comment_scan.malformed,
    })
}
