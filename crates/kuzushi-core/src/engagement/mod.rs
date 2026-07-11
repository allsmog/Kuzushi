use crate::fs_atomic::now_ms;
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const ENGAGEMENT_DIR: &str = "engagement";
pub const HARNESS_FILE: &str = "harness.toml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EngagementHarness {
    pub version: u32,
    pub target_root: String,
    pub generated_at_ms: u64,
    pub focus: Option<FocusIntent>,
    pub engines: Vec<HarnessEngine>,
    pub budget_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FocusIntent {
    pub raw: String,
    pub kind: FocusKind,
    pub cwe_tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FocusKind {
    SqlInjection,
    Xss,
    Ssrf,
    Authz,
    Deserialization,
    PathTraversal,
    CommandInjection,
    Crypto,
    Secrets,
    Unmapped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HarnessEngine {
    pub id: String,
    pub enabled: bool,
    pub estimated_cost_usd: Option<f64>,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EngagementHarnessRequest {
    pub focus: Option<String>,
    pub engines: Vec<String>,
    pub budget_usd: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EngagementHarnessReport {
    pub harness: EngagementHarness,
    pub path: PathBuf,
}

pub fn write_engagement_harness(
    workspace: &WorkspaceTarget,
    request: EngagementHarnessRequest,
) -> Result<EngagementHarnessReport> {
    let harness = build_engagement_harness(workspace, request);
    let body = toml::to_string_pretty(&harness).context("Could not serialize engagement harness")?;
    let path = crate::workspace::write_workspace_file(
        workspace.root(),
        PathBuf::from(ENGAGEMENT_DIR).join(HARNESS_FILE),
        body.as_bytes(),
    )
    .context("Could not write engagement harness")?;
    Ok(EngagementHarnessReport { harness, path })
}

pub fn engagement_harness_path(workspace: &WorkspaceTarget) -> PathBuf {
    workspace.root().join(ENGAGEMENT_DIR).join(HARNESS_FILE)
}

fn build_engagement_harness(
    workspace: &WorkspaceTarget,
    request: EngagementHarnessRequest,
) -> EngagementHarness {
    EngagementHarness {
        version: 1,
        target_root: workspace.root().display().to_string(),
        generated_at_ms: now_ms(),
        focus: request.focus.as_deref().map(parse_focus_intent),
        engines: harness_engines(request.engines),
        budget_usd: request.budget_usd,
    }
}

pub fn parse_focus_intent(raw: &str) -> FocusIntent {
    let normalized = raw.trim().to_ascii_lowercase();
    let (kind, cwe_tags) = focus_mapping(&normalized);
    FocusIntent {
        raw: raw.trim().to_string(),
        kind,
        cwe_tags,
    }
}

fn focus_mapping(normalized: &str) -> (FocusKind, Vec<String>) {
    let Some(rule) = FOCUS_RULES.iter().find(|rule| rule.matches(normalized)) else {
        return (FocusKind::Unmapped, Vec::new());
    };
    (rule.kind, cwes(rule.cwe_tags))
}

fn cwes(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

struct FocusRule {
    kind: FocusKind,
    cwe_tags: &'static [&'static str],
    needles: &'static [&'static str],
}

impl FocusRule {
    fn matches(&self, normalized: &str) -> bool {
        self.needles.iter().any(|needle| normalized.contains(needle))
    }
}

const FOCUS_RULES: &[FocusRule] = &[
    FocusRule {
        kind: FocusKind::SqlInjection,
        cwe_tags: &["CWE-89"],
        needles: &["sqli", "sql injection"],
    },
    FocusRule {
        kind: FocusKind::Xss,
        cwe_tags: &["CWE-79"],
        needles: &["xss", "cross-site"],
    },
    FocusRule {
        kind: FocusKind::Ssrf,
        cwe_tags: &["CWE-918"],
        needles: &["ssrf"],
    },
    FocusRule {
        kind: FocusKind::Authz,
        cwe_tags: &["CWE-639", "CWE-862"],
        needles: &["idor", "authz", "authorization"],
    },
    FocusRule {
        kind: FocusKind::Deserialization,
        cwe_tags: &["CWE-502"],
        needles: &["deserialization", "deserialize"],
    },
    FocusRule {
        kind: FocusKind::PathTraversal,
        cwe_tags: &["CWE-22"],
        needles: &["path traversal", "traversal"],
    },
    FocusRule {
        kind: FocusKind::CommandInjection,
        cwe_tags: &["CWE-78"],
        needles: &["command injection", "rce"],
    },
    FocusRule {
        kind: FocusKind::Crypto,
        cwe_tags: &["CWE-327"],
        needles: &["crypto", "cryptograph"],
    },
    FocusRule {
        kind: FocusKind::Secrets,
        cwe_tags: &["CWE-798"],
        needles: &["secret", "credential"],
    },
];

fn harness_engines(engines: Vec<String>) -> Vec<HarnessEngine> {
    if engines.is_empty() {
        return vec![default_engine("sast:scan"), default_engine("module-recommender:recommend")];
    }
    engines.into_iter().map(default_engine).collect()
}

fn default_engine(id: impl Into<String>) -> HarnessEngine {
    HarnessEngine {
        id: id.into(),
        enabled: true,
        estimated_cost_usd: None,
        reason: "operator selected".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn parses_known_focus_intents() {
        let focus = parse_focus_intent("focus on sqli");

        assert_eq!(focus.kind, FocusKind::SqlInjection);
        assert_eq!(focus.cwe_tags, vec!["CWE-89"]);
    }

    #[test]
    fn writes_harness_under_target_engagement_dir() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();

        let report = write_engagement_harness(
            &workspace,
            EngagementHarnessRequest {
                focus: Some("ssrf".to_string()),
                engines: vec!["taint-iris:hunt".to_string()],
                budget_usd: Some(12.5),
            },
        )
        .unwrap();

        assert_eq!(report.path, workspace.root().join("engagement/harness.toml"));
        let body = fs::read_to_string(report.path).unwrap();
        assert!(body.contains("taint-iris:hunt"));
        assert!(body.contains("CWE-918"));
    }

    #[cfg(unix)]
    #[test]
    fn harness_writer_rejects_symlinked_output_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        symlink(outside.path(), temp.path().join("engagement")).unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();

        assert!(write_engagement_harness(&workspace, EngagementHarnessRequest::default()).is_err());
        assert!(!outside.path().join(HARNESS_FILE).exists());
    }
}
