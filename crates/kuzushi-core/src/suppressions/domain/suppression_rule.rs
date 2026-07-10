use crate::findings::{Finding, Severity};
use crate::workspace::ScopeVerdict;
use serde::{Deserialize, Serialize};

/// Why a finding is suppressed. Shared vocabulary across false-positive
/// dismissal, scope gating, severity muting, and in-source ignore comments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuppressionReason {
    FalsePositive,
    AcceptableRisk,
    WontFix,
    UsedInTests,
    NoTimeToFix,
    OutOfScope,
}

impl SuppressionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalsePositive => "false-positive",
            Self::AcceptableRisk => "acceptable-risk",
            Self::WontFix => "wont-fix",
            Self::UsedInTests => "used-in-tests",
            Self::NoTimeToFix => "no-time-to-fix",
            Self::OutOfScope => "out-of-scope",
        }
    }

    /// Parse an operator-supplied reason token. Unknown tokens are an
    /// explicit error (no silent default), per the no-silent-fallback rule.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "false-positive" | "fp" => Some(Self::FalsePositive),
            "acceptable-risk" | "accepted-risk" | "risk" => Some(Self::AcceptableRisk),
            "wont-fix" | "wontfix" => Some(Self::WontFix),
            "used-in-tests" | "test" | "tests" => Some(Self::UsedInTests),
            "no-time-to-fix" | "no-time" => Some(Self::NoTimeToFix),
            "out-of-scope" | "oos" => Some(Self::OutOfScope),
            _ => None,
        }
    }
}

/// Where a suppression rule came from. Determines specificity ordering
/// during evaluation (most specific operator intent wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuppressionOrigin {
    /// `.kuzushi/v3/suppressions.toml`
    File,
    /// Compiled from the program-scope `scope.toml`.
    ScopeToml,
    /// `# kuzushi-ignore:` line comment in the source under review.
    InSourceComment,
    /// Compiled from the legacy `whitebox-suppressions.json` store.
    Whitebox,
}

impl SuppressionOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::ScopeToml => "scope-toml",
            Self::InSourceComment => "in-source-comment",
            Self::Whitebox => "whitebox",
        }
    }

    /// Lower rank = more specific = wins first-match ordering.
    /// comment > file > whitebox > scope.
    pub fn specificity_rank(self) -> u8 {
        match self {
            Self::InSourceComment => 0,
            Self::File => 1,
            Self::Whitebox => 2,
            Self::ScopeToml => 3,
        }
    }
}

/// A finding reference used inside a predicate. Stored as a fingerprint
/// (or fingerprint prefix); alias/identity resolution happens at the
/// tool boundary so this matcher stays pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRef(pub String);

impl FindingRef {
    pub fn matches(&self, finding: &Finding) -> bool {
        let reference = self.0.trim();
        if reference.is_empty() {
            return false;
        }
        if finding.identity_id.as_deref() == Some(reference) {
            return true;
        }
        finding.fingerprint.starts_with(reference)
    }
}

/// Conjunctive match predicate: every `Some(_)` field must match, and at
/// least one field must be `Some` (enforced at parse time). Compiled form:
/// path globs are `globset::GlobMatcher`.
#[derive(Debug, Clone)]
pub struct SuppressionPredicate {
    pub finding_id: Option<FindingRef>,
    pub rule_id: Option<String>,
    pub tool: Option<String>,
    pub path_glob: Option<globset::GlobMatcher>,
    pub module: Option<String>,
    pub severity_below: Option<Severity>,
    pub scope_status: Option<ScopeVerdict>,
}

impl SuppressionPredicate {
    pub fn empty() -> Self {
        Self {
            finding_id: None,
            rule_id: None,
            tool: None,
            path_glob: None,
            module: None,
            severity_below: None,
            scope_status: None,
        }
    }

    /// A predicate with no active field would match everything, which is
    /// never a valid authored rule.
    pub fn is_empty(&self) -> bool {
        self.finding_id.is_none()
            && self.rule_id.is_none()
            && self.tool.is_none()
            && self.path_glob.is_none()
            && self.module.is_none()
            && self.severity_below.is_none()
            && self.scope_status.is_none()
    }
}

#[derive(Debug, Clone)]
pub struct SuppressionRule {
    pub id: String,
    pub predicate: SuppressionPredicate,
    pub reason: SuppressionReason,
    pub statement: String,
    pub actor: String,
    pub created_at_unix: u64,
    pub expires_at_unix: Option<u64>,
    pub origin: SuppressionOrigin,
}

impl SuppressionRule {
    pub fn is_expired(&self, now_unix: u64) -> bool {
        matches!(self.expires_at_unix, Some(expiry) if now_unix >= expiry)
    }
}
