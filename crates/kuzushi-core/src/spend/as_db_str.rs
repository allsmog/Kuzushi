use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Operation {
    Triage,
    ClassifierGate,
    DeepAudit,
    FullModeMulti,
    Patch,
}

impl Operation {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Triage => "triage",
            Self::ClassifierGate => "classifier_gate",
            Self::DeepAudit => "deep_audit",
            Self::FullModeMulti => "full_mode_multi",
            Self::Patch => "patch",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "triage" => Some(Self::Triage),
            "classifier_gate" => Some(Self::ClassifierGate),
            "deep_audit" => Some(Self::DeepAudit),
            "full_mode_multi" => Some(Self::FullModeMulti),
            "patch" => Some(Self::Patch),
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
        ]
    }
}

#[derive(Debug)]
pub struct SpendTicket {
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
    /// Caps loaded once at init; mutated through [`SpendLimiter::set_cap`].
    pub(crate) caps: BTreeMap<Operation, f64>,
    /// Hard ceiling from `KUZUSHI_MAX_USD_PER_RUN`; `None` = unlimited.
    pub(crate) hard_ceiling: Option<f64>,
}
