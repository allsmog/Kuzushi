use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Operation {
    Triage,
    ClassifierGate,
    DeepAudit,
    FullModeMulti,
    Patch,
    ThreatModelStaged,
    FuzzAuthor,
}

impl Operation {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Triage => "triage",
            Self::ClassifierGate => "classifier_gate",
            Self::DeepAudit => "deep_audit",
            Self::FullModeMulti => "full_mode_multi",
            Self::Patch => "patch",
            Self::ThreatModelStaged => "threat_model_staged",
            Self::FuzzAuthor => "fuzz_author",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "triage" => Some(Self::Triage),
            "classifier_gate" => Some(Self::ClassifierGate),
            "deep_audit" => Some(Self::DeepAudit),
            "full_mode_multi" => Some(Self::FullModeMulti),
            "patch" => Some(Self::Patch),
            "threat_model_staged" => Some(Self::ThreatModelStaged),
            "fuzz_author" => Some(Self::FuzzAuthor),
            _ => None,
        }
    }

    pub const fn all() -> &'static [Self] {
        &[
            Self::Triage,
            Self::ClassifierGate,
            Self::DeepAudit,
            Self::FullModeMulti,
            Self::Patch,
            Self::ThreatModelStaged,
            Self::FuzzAuthor,
        ]
    }
}

#[derive(Debug)]
pub struct SpendTicket {
    pub(crate) ledger_id: String,
    pub(crate) id: i64,
    pub(crate) op: Operation,
    pub(crate) est_usd: f64,
    pub(crate) settled: bool,
}

impl SpendTicket {
    pub fn id(&self) -> i64 {
        self.id
    }
    pub fn op(&self) -> Operation {
        self.op
    }
    pub fn est_usd(&self) -> f64 {
        self.est_usd
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpendError {
    #[error(
        "budget exceeded for {op}: cap=${cap:.2}, committed=${committed:.2}, request=${request:.2}"
    )]
    Exceeded {
        op: &'static str,
        cap: f64,
        committed: f64,
        request: f64,
    },
    #[error(
        "hard ceiling exceeded: cap=${cap:.2}, committed=${committed:.2}, request=${request:.2}"
    )]
    HardCeilingExceeded {
        cap: f64,
        committed: f64,
        request: f64,
    },
}

pub struct SpendLimiter {
    pub(crate) state: Mutex<LimiterState>,
}

pub(crate) struct LimiterState {
    pub(crate) conn: Connection,
    pub(crate) ledger_id: String,
    /// Compatibility cache for infallible accessors. Admission reloads durable caps.
    pub(crate) caps: BTreeMap<Operation, f64>,
    /// Optional hard ceiling for the current limiter; `None` = unlimited.
    pub(crate) hard_ceiling: Option<f64>,
}
