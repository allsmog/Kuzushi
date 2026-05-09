use super::*;

pub(crate) const VALID_STAGES: &[&str] = &["s1", "s2", "s3", "s4"];

pub(crate) const VALID_METHODOLOGIES: &[&str] = &["pasta", "stride", "dread"];

pub(crate) const STRIDE_CATEGORIES: &[&str] = &[
    "spoofing",
    "tampering",
    "repudiation",
    "information-disclosure",
    "denial-of-service",
    "elevation-of-privilege",
];

#[derive(Debug, Clone, Copy)]
pub(crate) enum BuildFlavor {
    ThreatModel,
    RandoriPasta,
}

impl BuildFlavor {
    pub(crate) fn tool_name(self) -> &'static str {
        match self {
            Self::ThreatModel => "threat-model:build",
            Self::RandoriPasta => "randori:pasta",
        }
    }

    pub(crate) fn default_artifact_leaf(self) -> &'static str {
        match self {
            Self::ThreatModel => "threat-model-output",
            Self::RandoriPasta => "randori-output",
        }
    }

    pub(crate) fn provider(self) -> &'static str {
        "randori-pasta"
    }

    pub(crate) fn persists_document(self) -> bool {
        matches!(self, Self::ThreatModel)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ReadFlavor {
    ThreatModel,
    Randori,
}

impl ReadFlavor {
    pub(crate) fn tool_name(self) -> &'static str {
        match self {
            Self::ThreatModel => "threat-model:read",
            Self::Randori => "randori:threat-model",
        }
    }
}

#[derive(Debug)]
pub(crate) struct BuildInput {
    pub(crate) target: PathBuf,
    pub(crate) repo_name: String,
    pub(crate) methodology: String,
    pub(crate) slice: String,
    pub(crate) stages: Vec<String>,
    pub(crate) output_dir: String,
    pub(crate) max_elements: usize,
    pub(crate) max_threats: usize,
    pub(crate) emit_findings: bool,
    pub(crate) preserve_user_edits: bool,
    pub(crate) model: String,
}
