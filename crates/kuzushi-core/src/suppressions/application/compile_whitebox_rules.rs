use crate::proof::suppressions::WhiteboxSuppressionRecord;
use crate::suppressions::domain::{
    FindingRef, SuppressionOrigin, SuppressionPredicate, SuppressionReason, SuppressionRule,
};

/// Compile legacy whitebox JSON suppressions into unified rules so the store
/// keeps working through the single pipeline. Snippet-hash staleness stays in
/// `evaluate_whitebox_suppressions`; this bridge only carries the muting.
pub fn compile_whitebox_rules(records: &[WhiteboxSuppressionRecord]) -> Vec<SuppressionRule> {
    records.iter().map(compile_one).collect()
}

fn compile_one(record: &WhiteboxSuppressionRecord) -> SuppressionRule {
    SuppressionRule {
        id: format!("sup-wb-{}", record.id),
        predicate: whitebox_predicate(record),
        reason: whitebox_reason(&record.reason),
        statement: record.reason.clone(),
        actor: record.author.clone(),
        created_at_unix: record.created_at_unix,
        expires_at_unix: nonzero(record.expires_at_unix),
        origin: SuppressionOrigin::Whitebox,
    }
}

fn whitebox_predicate(record: &WhiteboxSuppressionRecord) -> SuppressionPredicate {
    if let Some(fingerprint) = &record.scope.finding_fingerprint {
        return SuppressionPredicate {
            finding_id: Some(FindingRef(fingerprint.clone())),
            ..SuppressionPredicate::empty()
        };
    }
    SuppressionPredicate {
        rule_id: Some(record.scope.rule_id.clone()),
        ..SuppressionPredicate::empty()
    }
}

/// Whitebox reasons are free text. Map to the closest structured reason,
/// preserving the original text in the rule statement. Unrecognized text
/// falls back to `AcceptableRisk` (the conservative "we accept this" bucket)
/// rather than dropping an operator-authored suppression.
fn whitebox_reason(text: &str) -> SuppressionReason {
    SuppressionReason::parse(text).unwrap_or(SuppressionReason::AcceptableRisk)
}

fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}
