use super::*;

pub(crate) const DEFAULT_THREAT_MODEL_GUIDANCE: &str = "Build a source-grounded threat model. Prioritize concrete trust boundaries, attacker-controlled entry points, security-sensitive data flows, and mitigations supported by repository evidence. Do not invent architecture or findings.";

pub(crate) const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;

pub(crate) const VALID_STAGES: &[&str] = &["s1", "s2", "s3", "s4"];

pub(crate) const VALID_METHODOLOGIES: &[&str] = &["pasta", "stride", "dread"];

pub(crate) const VALID_SOURCE_ARTIFACTS: &[&str] = &[
    "context",
    "source-code",
    "threat-model",
    "x-ray",
    "entry-points",
    "attachments",
    "none",
];

pub(crate) const DEFAULT_THREAT_MODEL_SOURCES: &[&str] =
    &["context", "source-code", "threat-model"];

pub(crate) const VALID_CONTEXT_MODES: &[&str] = &["auto", "refresh", "require", "off"];

pub(crate) const VALID_PIPELINES: &[&str] = &["single", "staged", "deterministic"];

pub(crate) const VALID_BUILD_MODES: &[&str] = &["build", "refine"];

pub(crate) const VALID_SEED_MODES: &[&str] = &["seeded", "fresh"];

pub(crate) const VALID_ADVISORY_MODES: &[&str] = &["off", "osv"];

pub(crate) const STRIDE_CATEGORIES: &[&str] = &[
    "spoofing",
    "tampering",
    "repudiation",
    "information-disclosure",
    "denial-of-service",
    "elevation-of-privilege",
];

/// Five-band likelihood ladder, least to most likely.
pub(crate) const LIKELIHOOD_BANDS: &[&str] =
    &["very_rare", "rare", "possible", "likely", "almost_certain"];

/// Asset sensitivity tiers for the document-level assets table.
pub(crate) const VALID_SENSITIVITIES: &[&str] = &["low", "medium", "high", "critical"];

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

    /// Truthful artifact provenance label: each flavor names itself, so a
    /// standard build is never labeled as the PASTA overlay.
    pub(crate) fn provider(self) -> &'static str {
        match self {
            Self::ThreatModel => "threat-model",
            Self::RandoriPasta => "randori-pasta",
        }
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

    pub(crate) fn default_methodology(self) -> &'static str {
        match self {
            Self::ThreatModel => "stride",
            Self::Randori => "pasta",
        }
    }
}

/// One operator-supplied known-vulnerability row from `vulnsFile`.
#[derive(Debug, Clone, Default)]
pub(crate) struct OperatorVulnRow {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) component: String,
    pub(crate) description: String,
}

#[derive(Debug, Default)]
pub(crate) struct BuildInput {
    pub(crate) roots: ThreatModelBuildRoots,
    pub(crate) repo_name: String,
    pub(crate) methodology: String,
    pub(crate) sources: Vec<String>,
    pub(crate) seeds: Vec<String>,
    pub(crate) design_docs: Vec<String>,
    pub(crate) slice: String,
    pub(crate) stages: Vec<String>,
    pub(crate) output_dir: String,
    pub(crate) context_mode: String,
    pub(crate) context_limit: usize,
    pub(crate) max_source_bytes: usize,
    pub(crate) max_elements: usize,
    pub(crate) max_threats: usize,
    pub(crate) max_output_tokens: u32,
    pub(crate) emit_findings: bool,
    pub(crate) preserve_user_edits: bool,
    pub(crate) prompt_override: Option<String>,
    pub(crate) model: String,
    pub(crate) pipeline: String,
    pub(crate) mode: String,
    pub(crate) seed_mode: String,
    pub(crate) budget_usd: Option<f64>,
    pub(crate) history_depth: usize,
    pub(crate) variant_scan: bool,
    pub(crate) advisories: String,
    pub(crate) offline: bool,
    pub(crate) advisory_fixtures: Option<Value>,
    pub(crate) vulns: Vec<OperatorVulnRow>,
    pub(crate) model_id: Option<ThreatModelId>,
    pub(crate) new_model: bool,
    pub(crate) activate: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThreatModelBuildRoots {
    pub workspace_root: PathBuf,
    pub analysis_root: PathBuf,
    pub scope: Option<ScopeRef>,
}

impl BuildInput {
    pub(crate) fn workspace_root(&self) -> &Path {
        &self.roots.workspace_root
    }

    pub(crate) fn analysis_root(&self) -> &Path {
        &self.roots.analysis_root
    }

    pub(crate) fn is_staged(&self) -> bool {
        self.pipeline == "staged"
    }

    pub(crate) fn is_refine(&self) -> bool {
        self.mode == "refine"
    }

    /// Fresh builds deliberately ignore the persisted model as seed context
    /// and do not carry forward its display identifiers.
    pub(crate) fn is_fresh(&self) -> bool {
        self.seed_mode == "fresh"
    }

    /// The one seeding decision. The persisted model reaches the prompt — the
    /// full document through the source bundle *and* the count summary in the
    /// prompt header — if and only if this is true. Every channel keys off
    /// this rather than re-deriving it, which is what let the full document
    /// ride an ungated `sources` entry while `seedMode` gated only the
    /// summary. Refine is separate: it derives from the persisted document
    /// by definition.
    pub(crate) fn embeds_prior_model(&self) -> bool {
        !self.is_fresh() && self.sources.iter().any(|source| source == "threat-model")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeding_input(seed_mode: &str, sources: &[&str]) -> BuildInput {
        BuildInput {
            seed_mode: seed_mode.to_string(),
            sources: sources.iter().map(|source| source.to_string()).collect(),
            ..BuildInput::default()
        }
    }

    #[test]
    fn prior_model_is_embedded_only_when_both_knobs_agree() {
        assert!(seeding_input("seeded", &["context", "threat-model"]).embeds_prior_model());
        assert!(!seeding_input("fresh", &["context", "threat-model"]).embeds_prior_model());
        assert!(!seeding_input("seeded", &["context"]).embeds_prior_model());
        assert!(!seeding_input("fresh", &["context"]).embeds_prior_model());
    }

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
