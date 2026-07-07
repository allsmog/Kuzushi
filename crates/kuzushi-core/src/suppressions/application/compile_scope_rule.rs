use crate::suppressions::domain::{
    SuppressionOrigin, SuppressionPredicate, SuppressionReason, SuppressionRule,
};
use crate::workspace::{ProgramScope, ScopeVerdict};

/// Compile the program scope into a single synthetic suppression rule that
/// annotates already-stored findings whose host resolves to `OutOfScope`.
///
/// Returns `None` for an empty scope. Pre-dispatch and pre-insert scope gates
/// (PR #64) are untouched; this only adds annotation over stored findings, and
/// never touches code findings (they carry no host).
pub fn compile_scope_rule(scope: &ProgramScope) -> Option<SuppressionRule> {
    if scope.is_empty() {
        return None;
    }
    let predicate = SuppressionPredicate {
        scope_status: Some(ScopeVerdict::OutOfScope),
        ..SuppressionPredicate::empty()
    };
    Some(SuppressionRule {
        id: "sup-scope-out-of-scope".to_string(),
        predicate,
        reason: SuppressionReason::OutOfScope,
        statement: "Host is out of program scope (scope.toml).".to_string(),
        actor: "system:scope".to_string(),
        created_at_unix: 0,
        expires_at_unix: None,
        origin: SuppressionOrigin::ScopeToml,
    })
}
