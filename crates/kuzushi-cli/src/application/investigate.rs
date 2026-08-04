use super::scan::{scan_command_with_requested_input, ScanScopeArgs};
use super::scan_gate::ScanGatePolicy;
use anyhow::Result;
use serde_json::{json, Value};
use std::path::PathBuf;

const STANDARD_TASKS: &[&str] = &[
    "dep-hygiene",
    "secret-scan",
    "license-scan",
    "iac-scan",
    "agentic-sast",
];

const DEEP_TASKS: &[&str] = &[
    "dep-hygiene",
    "secret-scan",
    "license-scan",
    "iac-scan",
    "agentic-sast",
    "taint-iris-next",
    "systems-hunt",
    "offense-review",
];

#[derive(Debug)]
pub(crate) struct InvestigateRequest {
    pub(crate) target: PathBuf,
    pub(crate) profile: String,
    pub(crate) plan: bool,
    pub(crate) json: bool,
    pub(crate) ci: bool,
    pub(crate) scope: ScanScopeArgs,
    pub(crate) gate: ScanGatePolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvestigationProfile {
    Standard,
    Deep,
    Prove,
    Fix,
}

impl InvestigationProfile {
    fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "standard" => Ok(Self::Standard),
            "deep" => Ok(Self::Deep),
            "prove" => Ok(Self::Prove),
            "fix" => Ok(Self::Fix),
            other => anyhow::bail!(
                "unsupported investigation profile {other:?}; expected standard, deep, prove, or fix"
            ),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Deep => "deep",
            Self::Prove => "prove",
            Self::Fix => "fix",
        }
    }

    const fn tasks(self) -> &'static [&'static str] {
        match self {
            Self::Standard => STANDARD_TASKS,
            Self::Deep | Self::Prove | Self::Fix => DEEP_TASKS,
        }
    }

    const fn proof_policy(self) -> &'static str {
        match self {
            Self::Standard => "review",
            Self::Deep => "corroborated-model-review",
            Self::Prove => "empirical",
            Self::Fix => "empirical-then-build-test-checked-patch-draft",
        }
    }

    const fn requests_patch(self) -> bool {
        matches!(self, Self::Fix)
    }
}

pub(crate) async fn investigate_command(request: InvestigateRequest) -> Result<()> {
    let profile = InvestigationProfile::parse(&request.profile)?;
    let mut input = scan_input_for_profile(profile);
    super::scan_shards::apply_scan_paths_scope(
        &mut input,
        &request.target,
        request.scope.shard.as_deref(),
        request.scope.shard_manifest.as_deref(),
        &request.scope.paths,
    )?;

    if request.plan {
        return emit_plan(profile, &input, request.json);
    }
    emit_execution_summary(profile, request.json, request.ci);
    let task_labels = profile
        .tasks()
        .iter()
        .map(|task| task.to_string())
        .collect();
    scan_command_with_requested_input(
        request.target,
        input,
        task_labels,
        request.json,
        request.ci,
        request.gate,
    )
    .await
}

fn scan_input_for_profile(profile: InvestigationProfile) -> Value {
    let mut input = json!({
        "mode": "standard",
        "taskMode": "manual",
        "tasks": profile.tasks(),
        "triage": true,
    });
    apply_post_processing(profile, &mut input);
    input
}

fn apply_post_processing(profile: InvestigationProfile, input: &mut Value) {
    if matches!(profile, InvestigationProfile::Standard) {
        return;
    }
    insert(input, "verify", json!(true));
    insert(input, "verifyWhen", json!("severity>=high"));
    insert(input, "verifyVotes", json!(2));
    insert(
        input,
        "verifyMax",
        json!(if matches!(profile, InvestigationProfile::Deep) {
            10
        } else {
            5
        }),
    );
    if matches!(
        profile,
        InvestigationProfile::Prove | InvestigationProfile::Fix
    ) {
        insert(input, "pocExecution", json!(true));
    }
    if profile.requests_patch() {
        insert(input, "autoPatch", json!(true));
        insert(input, "maxIterations", json!(3));
    }
}

fn insert(input: &mut Value, key: &str, value: Value) {
    if let Some(object) = input.as_object_mut() {
        object.insert(key.to_string(), value);
    }
}

fn emit_plan(profile: InvestigationProfile, input: &Value, json_output: bool) -> Result<()> {
    let plan = json!({
        "profile": profile.as_str(),
        "proofPolicy": profile.proof_policy(),
        "targetMutation": "none",
        "scanInput": input,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("PROFILE {}", profile.as_str());
        println!("PROOF_POLICY {}", profile.proof_policy());
        println!("TARGET_MUTATION none");
        println!("TASKS {}", profile.tasks().join(","));
        println!("SCAN_INPUT {}", serde_json::to_string(input)?);
    }
    Ok(())
}

fn emit_execution_summary(profile: InvestigationProfile, json: bool, ci: bool) {
    if json || ci {
        return;
    }
    eprintln!(
        "investigate: profile={} proof={} tasks={}",
        profile.as_str(),
        profile.proof_policy(),
        profile.tasks().join(",")
    );
    if profile.requests_patch() {
        eprintln!(
            "investigate: fix produces a build-and-test-checked patch draft; it does not modify the target working tree"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_profile_is_one_reviewed_scan_without_proof_or_patch() {
        let input = scan_input_for_profile(InvestigationProfile::Standard);

        assert_eq!(input["triage"], json!(true));
        assert!(input.get("verify").is_none());
        assert!(input.get("autoPatch").is_none());
        assert_eq!(input["tasks"], json!(STANDARD_TASKS));
    }

    #[test]
    fn deep_profile_uses_complementary_lenses_and_corroborated_review() {
        let input = scan_input_for_profile(InvestigationProfile::Deep);

        assert_eq!(input["tasks"], json!(DEEP_TASKS));
        assert_eq!(input["verify"], json!(true));
        assert_eq!(input["verifyVotes"], json!(2));
        assert_eq!(input["verifyMax"], json!(10));
        assert!(input.get("pocExecution").is_none());
    }

    #[test]
    fn prove_profile_requests_empirical_verification_without_patching() {
        let input = scan_input_for_profile(InvestigationProfile::Prove);

        assert_eq!(input["pocExecution"], json!(true));
        assert_eq!(input["verifyMax"], json!(5));
        assert!(input.get("autoPatch").is_none());
    }

    #[test]
    fn fix_profile_requires_empirical_verification_before_a_patch_draft() {
        let input = scan_input_for_profile(InvestigationProfile::Fix);

        assert_eq!(input["pocExecution"], json!(true));
        assert_eq!(input["autoPatch"], json!(true));
        assert_eq!(input["maxIterations"], json!(3));
    }

    #[test]
    fn profile_parser_is_closed_world() {
        assert_eq!(
            InvestigationProfile::parse("prove").unwrap(),
            InvestigationProfile::Prove
        );
        assert!(InvestigationProfile::parse("custom").is_err());
    }
}
