use super::prelude::*;
use super::*;

impl PersistedProofVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exploited => "exploited",
            Self::NotReproduced => "not_reproduced",
            Self::HarnessFailedToBuild => "harness_failed_to_build",
            Self::InfrastructureError => "infrastructure_error",
            Self::LanguageUnsupportedYet => "language_unsupported_yet",
            Self::InsufficientFindingDetail => "insufficient_finding_detail",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "exploited" => Self::Exploited,
            "not_reproduced" => Self::NotReproduced,
            "harness_failed_to_build" => Self::HarnessFailedToBuild,
            "infrastructure_error" => Self::InfrastructureError,
            "language_unsupported_yet" => Self::LanguageUnsupportedYet,
            "insufficient_finding_detail" => Self::InsufficientFindingDetail,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PersistedSandboxBackend {
    Bwrap,
    Podman,
    Plain,
}

impl PersistedSandboxBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bwrap => "bwrap",
            Self::Podman => "podman",
            Self::Plain => "plain",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "bwrap" => Self::Bwrap,
            "podman" => Self::Podman,
            "plain" => Self::Plain,
            _ => return None,
        })
    }
}

pub struct FindingStore {
    pub(crate) conn: Connection,
}
