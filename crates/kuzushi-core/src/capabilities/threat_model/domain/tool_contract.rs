use super::*;

pub(crate) const DEFAULT_THREAT_MODEL_GUIDANCE: &str = "Build a source-grounded threat model. Prioritize concrete trust boundaries, attacker-controlled entry points, security-sensitive data flows, and mitigations supported by repository evidence. Do not invent architecture or findings.";

pub(crate) const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;

pub(crate) const VALID_STAGES: &[&str] = &["s1", "s2", "s3", "s4"];

pub(crate) const VALID_METHODOLOGIES: &[&str] = &["pasta", "stride", "dread"];

pub(crate) const VALID_SOURCE_ARTIFACTS: &[&str] = &[
    "context",
    "threat-model",
    "x-ray",
    "entry-points",
    "none",
];

pub(crate) const VALID_CONTEXT_MODES: &[&str] = &["auto", "refresh", "require", "off"];

pub(crate) const VALID_PIPELINES: &[&str] = &["single", "staged", "deterministic"];

pub(crate) const VALID_BUILD_MODES: &[&str] = &["build", "refine"];

pub(crate) const VALID_ADVISORY_MODES: &[&str] = &["off", "osv"];

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

    pub(crate) fn default_output_dir(self, target: &Path, run_id: &str) -> String {
        let path = crate::run_artifacts::run_dir(target, run_id).join(self.default_artifact_leaf());
        path.strip_prefix(target)
            .unwrap_or(path.as_path())
            .to_string_lossy()
            .replace('\\', "/")
    }

    pub(crate) fn provider(self) -> &'static str {
        "randori-pasta"
    }

    pub(crate) fn persists_document(self) -> bool {
        matches!(self, Self::ThreatModel)
    }

    pub(crate) fn default_methodology(self) -> &'static str {
        match self {
            Self::ThreatModel => "stride",
            Self::RandoriPasta => "pasta",
        }
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
    pub(crate) sources: Vec<String>,
    pub(crate) seeds: Vec<String>,
    pub(crate) design_doc: Option<String>,
    pub(crate) slice: String,
    pub(crate) stages: Vec<String>,
    pub(crate) output_dir: String,
    pub(crate) context_mode: String,
    pub(crate) context_limit: usize,
    pub(crate) max_source_bytes: usize,
    pub(crate) max_elements: usize,
    pub(crate) max_threats: usize,
    pub(crate) emit_findings: bool,
    pub(crate) preserve_user_edits: bool,
    pub(crate) prompt_override: Option<String>,
    pub(crate) model: String,
    pub(crate) pipeline: String,
    pub(crate) mode: String,
    pub(crate) budget_usd: Option<f64>,
    pub(crate) history_depth: usize,
    pub(crate) variant_scan: bool,
    pub(crate) advisories: String,
    pub(crate) offline: bool,
    pub(crate) advisory_fixtures: Option<Value>,
}

impl BuildInput {
    pub(crate) fn is_staged(&self) -> bool {
        self.pipeline == "staged"
    }

    pub(crate) fn is_refine(&self) -> bool {
        self.mode == "refine"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_dir_uses_shared_run_dir() {
        let target = Path::new("/repo");

        assert_eq!(
            BuildFlavor::ThreatModel.default_output_dir(target, "run-1"),
            crate::run_artifacts::run_dir(target, "run-1")
                .join(BuildFlavor::ThreatModel.default_artifact_leaf())
                .strip_prefix(target)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        );
        assert_eq!(
            BuildFlavor::RandoriPasta.default_output_dir(target, "run-2"),
            crate::run_artifacts::run_dir(target, "run-2")
                .join(BuildFlavor::RandoriPasta.default_artifact_leaf())
                .strip_prefix(target)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        );
    }
}
