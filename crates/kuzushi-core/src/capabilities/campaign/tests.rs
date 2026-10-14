use super::*;
use crate::config::V2Config;
use crate::modules::ToolExecutionContext;
use crate::workspace::WorkspaceTarget;
use serde_json::json;
use tempfile::tempdir;

fn run_plan(root: &std::path::Path, input: serde_json::Value) -> Result<Value> {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    execute_campaign_plan(&input, &ctx)
}

fn run_status(root: &std::path::Path, input: serde_json::Value) -> Result<Value> {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    execute_campaign_status(&input, &ctx)
}

fn write_shard_manifest(root: &std::path::Path) {
    let dir = root.join(".kuzushi");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("shards.toml"),
        r#"
[shards.parsers]
paths = ["src/codec", "src/formats"]

[shards.api]
paths = ["src/api"]
"#,
    )
    .unwrap();
}

fn write_threat_model(root: &std::path::Path) {
    let dir = root.join(".kuzushi");
    std::fs::create_dir_all(&dir).unwrap();
    let document = json!({
        "document": {
            "threats": [
                {
                    "id": "T1",
                    "title": "Archive path traversal",
                    "severity": "critical",
                    "relatedCwe": ["CWE-22", "CWE-59"],
                    "description": "Extraction writes outside the target directory."
                },
                {
                    "id": "T2",
                    "title": "Weak token comparison",
                    "severity": "low",
                    "cwe": "CWE-208"
                }
            ]
        }
    });
    std::fs::write(
        dir.join("threat-model.json"),
        serde_json::to_string(&document).unwrap(),
    )
    .unwrap();
}

#[test]
fn plan_crosses_shards_with_threats_and_ranks_by_severity() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());

    let result = run_plan(temp.path(), json!({"campaignId": "camp-test"})).unwrap();

    let plan = &result["data"]["plan"];
    assert_eq!(plan["jobCount"], 4); // 2 shards × 2 threats
    let jobs = plan["jobs"].as_array().unwrap();
    // Critical threat (40 + 2 CWEs × 5 = 50) outranks low (10 + 5 = 15).
    assert_eq!(jobs[0]["threatId"], "T1");
    assert_eq!(jobs[0]["priority"], 50);
    assert_eq!(jobs[3]["threatId"], "T2");
    assert_eq!(jobs[3]["priority"], 15);
    assert_eq!(jobs[0]["state"], "planned");
    assert!(campaign_plan_path(temp.path(), "camp-test").exists());
}

#[test]
fn plan_seasons_a_full_triage_prompt_per_threat_job() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());

    let result = run_plan(
        temp.path(),
        json!({"campaignId": "camp-prompt", "shards": ["parsers"]}),
    )
    .unwrap();

    let jobs = result["data"]["plan"]["jobs"].as_array().unwrap().clone();
    let top = &jobs[0];
    let prompt_rel = top["promptPath"].as_str().unwrap();
    assert_eq!(top["input"]["TRIAGE_PROMPT"], prompt_rel);
    assert_eq!(top["input"]["shard"], "parsers");
    assert_eq!(top["input"]["paths"][0], "src/codec");
    let body = std::fs::read_to_string(temp.path().join(prompt_rel)).unwrap();
    // The override REPLACES the default prompt, so the file must carry it.
    assert!(body.contains(crate::runtime::DEFAULT_TRIAGE_PROMPT));
    assert!(body.contains("CWE-22"));
}

#[test]
fn plan_without_manifest_or_model_yields_one_whole_workspace_job() {
    let temp = tempdir().unwrap();

    let result = run_plan(temp.path(), json!({"campaignId": "camp-bare"})).unwrap();

    let plan = &result["data"]["plan"];
    assert_eq!(plan["jobCount"], 1);
    let job = &plan["jobs"][0];
    assert_eq!(job["shard"], "workspace");
    assert_eq!(job["threatId"], Value::Null);
    assert_eq!(job["promptPath"], Value::Null);
    assert_eq!(job["input"], json!({}));
    // An unseasoned plan is legal but must say so, in the document and the
    // operator-visible result line.
    assert_eq!(plan["threatCount"], 0);
    assert_eq!(plan["seasoned"], false);
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("unseasoned: no threat documents"));
}

/// A malformed persisted threat model must fail planning, not silently
/// degrade to an unseasoned plan that misrepresents campaign coverage.
#[test]
fn plan_errors_on_malformed_workspace_threat_model() {
    let temp = tempdir().unwrap();
    let dir = temp.path().join(".kuzushi");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("threat-model.json"), "{not json").unwrap();

    let error = run_plan(temp.path(), json!({"campaignId": "camp-broken"})).unwrap_err();

    assert!(error.to_string().contains("threat model"));
    assert!(!campaign_plan_path(temp.path(), "camp-broken").exists());
}

/// Documents that parse but yield zero threats[] would silently drop the
/// threat axis the operator supplied; the planner names them instead.
#[test]
fn plan_errors_when_supplied_documents_yield_no_threats() {
    let temp = tempdir().unwrap();
    let dir = temp.path().join(".kuzushi");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("threat-model.json"),
        json!({"document": {"threats": []}}).to_string(),
    )
    .unwrap();

    let error = run_plan(temp.path(), json!({"campaignId": "camp-empty"})).unwrap_err();

    assert!(error.to_string().contains("no threats[]"));
    assert!(error.to_string().contains("threat-model.json"));

    let models = temp.path().join("models");
    std::fs::create_dir_all(&models).unwrap();
    std::fs::write(
        models.join("empty.json"),
        json!({"summary": "x"}).to_string(),
    )
    .unwrap();
    let error = run_plan(
        temp.path(),
        json!({"campaignId": "camp-empty-dir", "modelsDir": "models"}),
    )
    .unwrap_err();
    assert!(error.to_string().contains("\"empty\""));
}

/// allowUnseasoned is the deliberate escape hatch for threats-less context
/// documents (pack distillations): planning proceeds unseasoned and the
/// result names the documents that steered nothing.
#[test]
fn allow_unseasoned_plans_past_an_empty_threat_document_and_names_it() {
    let temp = tempdir().unwrap();
    let dir = temp.path().join(".kuzushi");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("threat-model.json"),
        json!({"document": {"threats": []}}).to_string(),
    )
    .unwrap();

    let result = run_plan(
        temp.path(),
        json!({"campaignId": "camp-unseasoned", "allowUnseasoned": true}),
    )
    .unwrap();

    let summary = result["summary"].as_str().unwrap();
    assert!(summary.contains("unseasoned"));
    assert!(summary.contains("threat-model.json"));
    assert!(summary.contains("allowUnseasoned"));
    let plan_path = campaign_plan_path(temp.path(), "camp-unseasoned");
    let plan: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(plan_path).unwrap()).unwrap();
    assert_eq!(plan["threatCount"], json!(0));
    assert_eq!(plan["seasoned"], json!(false));
    assert_eq!(plan["unseasonedDocuments"], json!(["threat-model.json"]));
}

#[test]
fn plan_refuses_a_degenerate_cross_product_instead_of_materializing_it() {
    let temp = tempdir().unwrap();
    let models: Vec<String> = (0..100_001).map(|index| format!("m{index}")).collect();

    let error = run_plan(
        temp.path(),
        json!({"campaignId": "camp-huge", "models": models}),
    )
    .unwrap_err();

    assert!(error.to_string().contains("100001 cells"));
}

#[test]
fn shard_manifest_rejects_blank_and_non_string_paths() {
    let temp = tempdir().unwrap();
    let dir = temp.path().join(".kuzushi");
    std::fs::create_dir_all(&dir).unwrap();

    // A blank path would silently widen the shard to the whole workspace.
    std::fs::write(dir.join("shards.toml"), "[shards.a]\npaths = [\"\"]\n").unwrap();
    let error = run_plan(temp.path(), json!({"campaignId": "c1"})).unwrap_err();
    assert!(error.to_string().contains("blank path"), "{error:#}");

    // A non-string entry would silently shrink the shard's scope.
    std::fs::write(
        dir.join("shards.toml"),
        "[shards.a]\npaths = [\"src\", 42]\n",
    )
    .unwrap();
    let error = run_plan(temp.path(), json!({"campaignId": "c2"})).unwrap_err();
    assert!(error.to_string().contains("must all be strings"));

    // An empty [shards] table would plan zero jobs while looking successful.
    std::fs::write(dir.join("shards.toml"), "[shards]\n").unwrap();
    let error = run_plan(temp.path(), json!({"campaignId": "c3"})).unwrap_err();
    assert!(error.to_string().contains("no shard entries"));
}

#[test]
fn plan_reports_jobs_dropped_by_the_cap_instead_of_hiding_them() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());

    let result = run_plan(temp.path(), json!({"campaignId": "camp-cap", "maxJobs": 3})).unwrap();

    assert_eq!(result["data"]["jobCount"], 3);
    assert_eq!(result["data"]["droppedJobs"], 1);
}

/// The PL1 degeneracy: many threats saturate the CWE bonus and tie on
/// priority (e.g. everything at 55). The cap must then spread jobs across
/// shards instead of filling early shards and silently starving late ones.
#[test]
fn plan_cap_spreads_tied_priorities_across_shards() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    let threats: Vec<Value> = (1..=4)
        .map(|index| {
            json!({
                "id": format!("T{index}"),
                "title": format!("tied threat {index}"),
                "severity": "high",
                "relatedCwe": ["CWE-1", "CWE-2", "CWE-3", "CWE-4", "CWE-5"],
            })
        })
        .collect();
    let dir = temp.path().join(".kuzushi");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("threat-model.json"),
        serde_json::to_string(&json!({"document": {"threats": threats}})).unwrap(),
    )
    .unwrap();

    // 2 shards × 4 threats = 8 jobs, all priority 30 + 25 = 55; keep 4.
    let result = run_plan(
        temp.path(),
        json!({"campaignId": "camp-tied", "maxJobs": 4}),
    )
    .unwrap();

    let plan = &result["data"]["plan"];
    let jobs = plan["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 4);
    let per_shard = |name: &str| jobs.iter().filter(|job| job["shard"] == name).count();
    assert_eq!(per_shard("parsers"), 2, "cap must not starve either shard");
    assert_eq!(per_shard("api"), 2, "cap must not starve either shard");
    assert_eq!(plan["droppedJobs"], 4);
    assert_eq!(plan["droppedByShard"], json!({"api": 2, "parsers": 2}));
    assert_eq!(plan["droppedTopPriority"], 55);
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("top dropped priority 55"));
}

/// Same inputs must produce the same job sequence: dispatch order is part
/// of the plan contract, not an accident of hash iteration.
#[test]
fn plan_job_order_is_deterministic_across_runs() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());

    let sequence = |id: &str| {
        let result = run_plan(temp.path(), json!({"campaignId": id})).unwrap();
        result["data"]["plan"]["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|job| {
                (
                    job["shard"].as_str().unwrap().to_string(),
                    job["threatId"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect::<Vec<_>>()
    };

    assert_eq!(sequence("camp-det-a"), sequence("camp-det-b"));
}

#[test]
fn plan_rejects_a_shard_missing_from_the_manifest() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());

    let error = run_plan(
        temp.path(),
        json!({"campaignId": "camp-bad", "shards": ["nope"]}),
    )
    .unwrap_err();

    assert!(error.to_string().contains("nope"), "{error:#}");
}

#[test]
fn status_folds_queue_states_over_planned_jobs() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());
    run_plan(temp.path(), json!({"campaignId": "camp-status"})).unwrap();
    let queue = json!({
        "jobs": {
            "job-001": {"state": "running", "runId": "run-x", "attempts": 1},
            "job-002": {
                "state": "completed",
                "runId": "run-y",
                "costUsd": 1.25,
                "providerSpendUnresolved": true,
                "exitCode": 0
            },
        }
    });
    write_json_atomic(&campaign_queue_path(temp.path(), "camp-status"), &queue).unwrap();

    let result = run_status(temp.path(), json!({"campaignId": "camp-status"})).unwrap();

    let states = &result["data"]["states"];
    assert_eq!(states["running"], 1);
    assert_eq!(states["completed"], 1);
    assert_eq!(states["planned"], 2);
    assert_eq!(result["data"]["totalCostUsd"], 1.25);
    assert_eq!(result["data"]["providerSpendUnresolved"], true);
    assert_eq!(result["data"]["trend"]["campaignSpendUsd"], 1.25);
    assert_eq!(result["data"]["trend"]["providerSpendUnresolved"], true);
    let jobs = result["data"]["jobs"].as_array().unwrap();
    let running = jobs.iter().find(|job| job["jobId"] == "job-001").unwrap();
    assert_eq!(running["doneSentinel"], false);
}

#[test]
fn status_refuses_a_malformed_queue_instead_of_forging_planned_state() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    run_plan(temp.path(), json!({"campaignId": "camp-corrupt"})).unwrap();
    std::fs::write(campaign_queue_path(temp.path(), "camp-corrupt"), "{").unwrap();

    let error = run_status(temp.path(), json!({"campaignId": "camp-corrupt"})).unwrap_err();

    assert!(error.to_string().contains("no readable queue"));
}

#[test]
fn status_lists_all_campaigns_when_no_id_is_given() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    run_plan(temp.path(), json!({"campaignId": "camp-a"})).unwrap();
    run_plan(temp.path(), json!({"campaignId": "camp-b"})).unwrap();

    let result = run_status(temp.path(), json!({})).unwrap();

    let campaigns = result["data"]["campaigns"].as_array().unwrap();
    assert_eq!(campaigns.len(), 2);
    assert_eq!(campaigns[0]["campaignId"], "camp-a");
}

#[test]
fn models_dir_documents_compound_across_subsystem_files() {
    let temp = tempdir().unwrap();
    let models = temp.path().join("models");
    std::fs::create_dir_all(&models).unwrap();
    std::fs::write(
        models.join("subsystem-a.json"),
        json!({"threats": [{"id": "A1", "title": "a", "severity": "high", "cwe": "CWE-787"}]})
            .to_string(),
    )
    .unwrap();
    std::fs::write(
        models.join("subsystem-b.json"),
        json!({"threats": [{"id": "B1", "title": "b", "severity": "medium"}]}).to_string(),
    )
    .unwrap();

    let result = run_plan(
        temp.path(),
        json!({"campaignId": "camp-dir", "modelsDir": "models"}),
    )
    .unwrap();

    let jobs = result["data"]["plan"]["jobs"].as_array().unwrap().clone();
    assert_eq!(jobs.len(), 2); // one pseudo-shard × two subsystem threats
    assert_eq!(jobs[0]["threatId"], "A1");
    assert_eq!(jobs[0]["threatSource"], "subsystem-a");
    assert_eq!(jobs[1]["threatSource"], "subsystem-b");
}

#[test]
fn plan_adapts_scope_file_input_for_agentic_sast_jobs() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());
    for file in ["src/codec/lz.c", "src/formats/tar.c", "src/api/http.c"] {
        let path = temp.path().join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "int main() {}\n").unwrap();
    }

    let result = run_plan(
        temp.path(),
        json!({
            "campaignId": "camp-agentic",
            "tool": "agentic-sast:scan",
            "promptOption": "AGENTIC_SAST_PROMPT",
        }),
    )
    .unwrap();

    let jobs = result["data"]["plan"]["jobs"].as_array().unwrap().clone();
    let parsers = jobs
        .iter()
        .find(|job| job["shard"] == "parsers")
        .expect("parsers job planned");
    // Scope-file tools reject `paths`/`shard`; the input must carry only
    // the materialized scope file plus the prompt option.
    let input = parsers["input"].as_object().unwrap();
    assert!(!input.contains_key("paths"));
    assert!(!input.contains_key("shard"));
    let scope_rel = input["scopeFile"].as_str().unwrap();
    let scope_body = std::fs::read_to_string(temp.path().join(scope_rel)).unwrap();
    assert_eq!(scope_body, "src/codec/lz.c\nsrc/formats/tar.c\n");
    // Non-TRIAGE prompt options compose with the builtin prompt, so the
    // seasoning must stay a focus-only fragment.
    let prompt_rel = input["AGENTIC_SAST_PROMPT"].as_str().unwrap();
    let prompt_body = std::fs::read_to_string(temp.path().join(prompt_rel)).unwrap();
    assert!(!prompt_body.contains(crate::runtime::DEFAULT_TRIAGE_PROMPT));
    assert!(prompt_body.starts_with("## Campaign focus"));
}

#[test]
fn plan_refuses_scope_file_jobs_over_missing_shard_paths() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());
    // No files exist under the manifest paths.

    let error = run_plan(
        temp.path(),
        json!({"campaignId": "camp-empty", "tool": "agentic-sast:scan"}),
    )
    .unwrap_err();

    assert!(error.to_string().contains("matched no files"));
}

#[test]
fn plan_seasoning_carries_installed_workspace_fragment() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());
    let prompts = temp.path().join(".kuzushi/prompts/sast");
    std::fs::create_dir_all(&prompts).unwrap();
    std::fs::write(prompts.join("triage.md"), "PACK CALIBRATION RULES\n").unwrap();

    let result = run_plan(
        temp.path(),
        json!({"campaignId": "camp-frag", "shards": ["parsers"]}),
    )
    .unwrap();

    // Explicit TRIAGE_PROMPT bypasses the workspace auto-load, so the
    // seasoning file must carry the installed fragment itself.
    let jobs = result["data"]["plan"]["jobs"].as_array().unwrap().clone();
    let prompt_rel = jobs[0]["promptPath"].as_str().unwrap();
    let body = std::fs::read_to_string(temp.path().join(prompt_rel)).unwrap();
    assert!(body.contains(crate::runtime::DEFAULT_TRIAGE_PROMPT));
    assert!(body.contains("PACK CALIBRATION RULES"));
    let baseline = body.find(crate::runtime::DEFAULT_TRIAGE_PROMPT).unwrap();
    let fragment = body.find("PACK CALIBRATION RULES").unwrap();
    let focus = body.find("## Campaign focus").unwrap();
    assert!(baseline < fragment && fragment < focus);
}

#[test]
fn coverage_report_folds_campaigns_and_counts_shard_findings() {
    use super::coverage::{coverage_report, CoverageCellState, CoverageFinding};
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());
    run_plan(temp.path(), json!({"campaignId": "camp-cov"})).unwrap();
    // Dispatcher truth: first planned job completed, everything else untouched.
    let plan =
        crate::bounded_file::read_utf8_text(&campaign_plan_path(temp.path(), "camp-cov"), 1 << 20)
            .unwrap();
    let plan: Value = serde_json::from_str(&plan).unwrap();
    let first_job = plan["jobs"][0]["jobId"].as_str().unwrap();
    let first_shard = plan["jobs"][0]["shard"].as_str().unwrap().to_string();
    std::fs::write(
        campaign_dir(temp.path(), "camp-cov").join("queue.json"),
        json!({"jobs": {first_job: {"state": "completed"}}}).to_string(),
    )
    .unwrap();

    let findings = vec![
        CoverageFinding {
            file_path: "src/codec/lz.c".to_string(),
            confirmed: true,
        },
        CoverageFinding {
            file_path: "src/codec2/other.c".to_string(),
            confirmed: false,
        },
    ];
    let report = coverage_report(temp.path(), &findings).unwrap();

    assert_eq!(report.campaign_count, 1);
    assert_eq!(report.columns, vec!["threat-model.json".to_string()]);
    let parsers = report
        .rows
        .iter()
        .find(|row| row.shard == "parsers")
        .unwrap();
    // src/codec2 must NOT leak into the src/codec prefix.
    assert_eq!(parsers.finding_count, 1);
    assert_eq!(parsers.confirmed_count, 1);
    let first_row = report
        .rows
        .iter()
        .find(|row| row.shard == first_shard)
        .unwrap();
    // Only one of the source's two threats completed for this shard, so the
    // cell reports Partial — never full credit for partial coverage.
    assert_eq!(first_row.cells, vec![CoverageCellState::Partial]);
    let other = report
        .rows
        .iter()
        .find(|row| row.shard != first_shard)
        .unwrap();
    assert_eq!(other.cells, vec![CoverageCellState::Planned]);
}

/// A corrupt campaign directory is skipped from the fold (one bad dir must
/// not blind the whole matrix) but the skip is DISCLOSED — silently smaller
/// coverage would make "never" cells lie.
#[test]
fn coverage_report_discloses_unreadable_campaign_dirs() {
    use super::coverage::coverage_report;
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());
    run_plan(temp.path(), json!({"campaignId": "camp-good"})).unwrap();
    let corrupt = campaign_dir(temp.path(), "camp-corrupt");
    std::fs::create_dir_all(&corrupt).unwrap();
    std::fs::write(corrupt.join("plan.json"), "{not json").unwrap();

    let report = coverage_report(temp.path(), &[]).unwrap();

    assert_eq!(report.campaign_count, 1);
    assert_eq!(report.unreadable_campaigns, 1);
}

#[test]
fn coverage_excludes_preparation_and_modern_non_shard_jobs() {
    let root = tempdir().unwrap();
    let dir = campaign_dir(root.path(), "progress-audit");
    std::fs::create_dir_all(&dir).unwrap();
    let plan = json!({"campaignId":"progress-audit", "tool":"sast:scan", "jobs":[
        {"jobId":"map-only","tool":"context:build","shard":"workspace","input":{}},
        {"jobId":"unknown","tool":"unknown:tool","shard":"workspace","input":{}},
        {"jobId":"modern-study","tool":"sast:scan","input":{}},
        {"jobId":"legacy-discovery","shard":"workspace","input":{}}
    ]});
    std::fs::write(dir.join("plan.json"), serde_json::to_vec(&plan).unwrap()).unwrap();
    let jobs = ["map-only", "unknown", "modern-study", "legacy-discovery"]
        .into_iter()
        .map(|id| (id.to_string(), json!({"state":"completed"})))
        .collect::<serde_json::Map<_, _>>();
    std::fs::write(dir.join("queue.json"), json!({"jobs":jobs}).to_string()).unwrap();
    let report = coverage::coverage_report(root.path(), &[]).unwrap();
    assert_eq!(report.excluded_jobs, 3);
    assert_eq!(report.columns, [coverage::UNSEASONED_COLUMN]);
    assert_eq!(
        report.rows[0].cells,
        [coverage::CoverageCellState::Completed]
    );
    let mut no_discovery = plan;
    no_discovery["jobs"].as_array_mut().unwrap().pop();
    std::fs::write(dir.join("plan.json"), no_discovery.to_string()).unwrap();
    let report = coverage::coverage_report(root.path(), &[]).unwrap();
    assert_eq!(report.excluded_jobs, 3);
    assert!(report.columns.is_empty());
    assert!(report.rows[0].cells.is_empty());
}

/// A cell is Completed only when EVERY threat planned from its source
/// completed for the shard; a lone completed threat yields Partial above,
/// and all-completed yields Completed here.
#[test]
fn coverage_cell_completes_only_when_every_threat_of_the_source_completed() {
    use super::coverage::{coverage_report, CoverageCellState};
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());
    run_plan(temp.path(), json!({"campaignId": "camp-all"})).unwrap();
    let plan =
        crate::bounded_file::read_utf8_text(&campaign_plan_path(temp.path(), "camp-all"), 1 << 20)
            .unwrap();
    let plan: Value = serde_json::from_str(&plan).unwrap();
    let done_shard = plan["jobs"][0]["shard"].as_str().unwrap().to_string();
    let done: serde_json::Map<String, Value> = plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|job| job["shard"] == done_shard.as_str())
        .map(|job| {
            (
                job["jobId"].as_str().unwrap().to_string(),
                json!({"state": "completed"}),
            )
        })
        .collect();
    std::fs::write(
        campaign_dir(temp.path(), "camp-all").join("queue.json"),
        json!({ "jobs": done }).to_string(),
    )
    .unwrap();

    let report = coverage_report(temp.path(), &[]).unwrap();

    let done_row = report
        .rows
        .iter()
        .find(|row| row.shard == done_shard)
        .unwrap();
    assert_eq!(done_row.cells, vec![CoverageCellState::Completed]);
}

#[test]
fn plan_fill_gaps_skips_cells_the_coverage_fold_reports_covered() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());
    run_plan(temp.path(), json!({"campaignId": "camp-first"})).unwrap();
    let plan = crate::bounded_file::read_utf8_text(
        &campaign_plan_path(temp.path(), "camp-first"),
        1 << 20,
    )
    .unwrap();
    let plan: Value = serde_json::from_str(&plan).unwrap();
    let done_job = plan["jobs"][0]["jobId"].as_str().unwrap();
    let done_shard = plan["jobs"][0]["shard"].as_str().unwrap().to_string();
    std::fs::write(
        campaign_dir(temp.path(), "camp-first").join("queue.json"),
        json!({"jobs": {done_job: {"state": "completed"}}}).to_string(),
    )
    .unwrap();

    // Coverage is threat-granular: completing ONE threat's job skips only
    // that threat's cell. The shard's OTHER threat is still a gap and must
    // be re-planned — one finished threat never hides its document's rest.
    let done_threat = plan["jobs"][0]["threatId"].as_str().unwrap().to_string();
    let gap = run_plan(
        temp.path(),
        json!({"campaignId": "camp-gaps", "fillGaps": true}),
    )
    .unwrap();
    assert_eq!(gap["data"]["jobCount"], 3);
    assert_eq!(gap["data"]["skippedCoveredCells"], 1);
    assert_eq!(gap["data"]["fillGaps"], true);
    let gap_plan = &gap["data"]["plan"];
    assert_eq!(gap_plan["fillGaps"], true);
    assert_eq!(gap_plan["skippedCoveredCells"], 1);
    let done_shard_jobs: Vec<&Value> = gap_plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|job| job["shard"].as_str().unwrap() == done_shard)
        .collect();
    assert_eq!(
        done_shard_jobs.len(),
        1,
        "the uncovered threat is re-planned"
    );
    assert_ne!(
        done_shard_jobs[0]["threatId"].as_str().unwrap(),
        done_threat
    );

    // Failed cells stay gaps: a re-plan after failure must re-cover them.
    std::fs::write(
        campaign_dir(temp.path(), "camp-first").join("queue.json"),
        json!({"jobs": {done_job: {"state": "failed"}}}).to_string(),
    )
    .unwrap();
    let refill = run_plan(
        temp.path(),
        json!({"campaignId": "camp-refill", "fillGaps": true}),
    )
    .unwrap();
    assert_eq!(refill["data"]["jobCount"], 4);
    assert_eq!(refill["data"]["skippedCoveredCells"], 0);

    // Without fillGaps the full matrix plans regardless of coverage.
    let full = run_plan(temp.path(), json!({"campaignId": "camp-full"})).unwrap();
    assert_eq!(full["data"]["jobCount"], 4);
    assert_eq!(full["data"]["fillGaps"], false);
}

#[test]
fn snapshot_joins_dispatcher_budget_and_run_finding_counts() {
    use super::snapshot::load_campaign_snapshot;
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    write_threat_model(temp.path());
    run_plan(temp.path(), json!({"campaignId": "camp-v2"})).unwrap();
    let plan =
        crate::bounded_file::read_utf8_text(&campaign_plan_path(temp.path(), "camp-v2"), 1 << 20)
            .unwrap();
    let plan: Value = serde_json::from_str(&plan).unwrap();
    let first_job = plan["jobs"][0]["jobId"].as_str().unwrap();
    std::fs::write(
        campaign_dir(temp.path(), "camp-v2").join("queue.json"),
        json!({
            "budgetUsd": 15.0,
            "jobBudgetUsd": 5.0,
            "pausedUntilMs": 12345,
            "jobs": {first_job: {
                "state": "completed",
                "costUsd": 3.25,
                "runId": "camp-v2-job-a1",
            }},
        })
        .to_string(),
    )
    .unwrap();
    // Finalized child-run metadata: the fold joins `findings` from run.json.
    let run_dir = crate::workspace::workspace_state_dir(temp.path())
        .join("runs")
        .join("camp-v2-job-a1");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(
        run_dir.join("run.json"),
        json!({"runId": "camp-v2-job-a1", "status": "completed", "findings": 7}).to_string(),
    )
    .unwrap();

    let snapshot = load_campaign_snapshot(temp.path(), "camp-v2").unwrap();

    assert_eq!(snapshot.budget_usd, Some(15.0));
    assert_eq!(snapshot.job_budget_usd, Some(5.0));
    assert_eq!(snapshot.paused_until_ms, Some(12345));
    assert_eq!(snapshot.total_cost_usd, 3.25);
    let first = snapshot
        .jobs
        .iter()
        .find(|job| job.job_id == first_job)
        .unwrap();
    assert_eq!(first.findings, Some(7));
    // Jobs without a finalized run carry no count rather than a fake zero.
    let untouched = snapshot
        .jobs
        .iter()
        .find(|job| job.job_id != first_job)
        .unwrap();
    assert_eq!(untouched.findings, None);
}

#[test]
fn coverage_without_a_findings_store_states_that_it_counted_nothing() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };

    let result = execute_campaign_coverage(&json!({}), &ctx).unwrap();

    assert_eq!(result["data"]["findingLedger"], "no-store");
    let output = result["output"].as_str().unwrap();
    assert!(
        output.contains("shard finding counts are NOT measured"),
        "{output}"
    );
}

#[test]
fn status_reports_workspace_trend_with_spend_even_without_a_findings_store() {
    let temp = tempdir().unwrap();
    write_shard_manifest(temp.path());
    run_plan(temp.path(), json!({"campaignId": "camp-trend"})).unwrap();
    let queue = json!({
        "jobs": {
            "job-001": {"state": "completed", "costUsd": 4.5, "exitCode": 0},
            "job-002": {"state": "completed", "costUsd": 0.5, "exitCode": 0},
        }
    });
    write_json_atomic(&campaign_queue_path(temp.path(), "camp-trend"), &queue).unwrap();

    let single = run_status(temp.path(), json!({"campaignId": "camp-trend"})).unwrap();
    let all = run_status(temp.path(), json!({})).unwrap();

    for status in [&single, &all] {
        assert_eq!(
            status["data"]["historyWindow"],
            json!({
                "selection":"recent-valid-lines", "maxSnapshots":90, "maxReadBytes":1048576
            })
        );
    }

    // Trend is workspace-level, so both status shapes carry the same object.
    for trend in [&single["data"]["trend"], &all["data"]["trend"]] {
        assert_eq!(trend["campaignSpendUsd"], 5.0);
        assert_eq!(trend["decidedFindings"], 0);
        // No store is no database to have failed, so the zero stands.
        assert_eq!(trend["decisionsUnreadable"], false);
        assert_eq!(trend["fpRate"], serde_json::Value::Null);
        assert_eq!(trend["costPerConfirmedUsd"], serde_json::Value::Null);
    }
    // Every status run records a deduped history snapshot and carries the
    // bounded window back as trendHistory — two identical runs, one line.
    for history in [
        &single["data"]["trendHistory"],
        &all["data"]["trendHistory"],
    ] {
        let rows = history.as_array().expect("trendHistory array");
        assert_eq!(rows.len(), 1, "{history}");
        assert_eq!(rows[0]["campaignSpendUsd"], 5.0);
        assert_eq!(rows[0]["fpRate"], serde_json::Value::Null);
    }
    let history_file = super::trend_history::trend_history_path(temp.path());
    assert_eq!(
        std::fs::read_to_string(history_file)
            .unwrap()
            .lines()
            .count(),
        1,
        "identical consecutive status runs must not grow the history file"
    );
}

/// Perf baseline generator + timer (task queue #38). Ignored by default:
/// run with `cargo test -p kuzushi-core --lib -- --ignored perf_baseline`
/// and read the eprintln table. Synthetic data lives only inside this
/// test — no shipping code path generates it.
#[test]
#[ignore = "perf baseline; run explicitly and read timings"]
fn perf_baseline_folds_over_10k_findings_30k_decisions() {
    use crate::findings::{FindingStore, ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
    use std::time::Instant;

    const FINDINGS: usize = 1_000;
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_shard_manifest(root);
    write_threat_model(root);
    run_plan(root, json!({"campaignId": "perf-camp"})).unwrap();

    let workspace = crate::workspace::WorkspaceTarget::new(root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("perf-run", root, "running")
        .unwrap();

    let decision = |verdict| ReviewDecision {
        verdict,
        author: TriageAuthor::Human,
        confidence: 1.0,
        rationale: "perf".to_string(),
        dismiss_reason: None,
        actor: None,
    };
    let generation = Instant::now();
    for index in 0..FINDINGS {
        let shard_dir = if index % 2 == 0 {
            "src/codec"
        } else {
            "src/api"
        };
        let finding = crate::findings::Finding::new_tool(
            "perf-fixture",
            format!("perf-rule-{}", index % 40),
            format!("{shard_dir}/file{}.c", index % 200),
            (index % 900) as u32 + 1,
            None,
            match index % 4 {
                0 => crate::findings::Severity::Critical,
                1 => crate::findings::Severity::High,
                2 => crate::findings::Severity::Medium,
                _ => crate::findings::Severity::Low,
            },
            format!("perf finding {index} CWE-{}", 100 + index % 50),
        );
        let id = store.insert_finding("perf-run", &finding).unwrap();
        // Three decisions per finding = 30k records, exercising the
        // latest-decision-wins reversal on every finding.
        store
            .append_user_review_decision(id, &decision(ReviewDecisionVerdict::Confirmed))
            .unwrap();
        store
            .append_user_review_decision(
                id,
                &decision(ReviewDecisionVerdict::RejectedFalsePositive),
            )
            .unwrap();
        let last = match index % 3 {
            0 => ReviewDecisionVerdict::Confirmed,
            1 => ReviewDecisionVerdict::Deferred,
            _ => ReviewDecisionVerdict::RejectedFalsePositive,
        };
        store
            .append_user_review_decision(id, &decision(last))
            .unwrap();
    }
    eprintln!(
        "PERF store generation: {:?} ({FINDINGS} findings + {} decisions through the event-sourced writer)",
        generation.elapsed(),
        FINDINGS * 3
    );

    let timer = Instant::now();
    let findings = store.list_all_findings().unwrap();
    eprintln!(
        "PERF list_all_findings: {:?} ({} rows)",
        timer.elapsed(),
        findings.len()
    );

    let timer = Instant::now();
    let records = store.list_review_decisions_for_findings(&findings).unwrap();
    eprintln!(
        "PERF list_review_decisions_for_findings: {:?} ({} rows)",
        timer.elapsed(),
        records.len()
    );

    let timer = Instant::now();
    let narrow_records = store.list_all_review_decisions().unwrap();
    eprintln!(
        "PERF list_all_review_decisions (subject projection, no finding load): {:?} ({} rows)",
        timer.elapsed(),
        narrow_records.len()
    );
    assert_eq!(narrow_records.len(), records.len());

    let timer = Instant::now();
    let metrics = super::trend::trend_metrics(&records, 123.0);
    eprintln!(
        "PERF trend_metrics fold: {:?} (decided {})",
        timer.elapsed(),
        metrics.decided_findings
    );

    let timer = Instant::now();
    let confirmed = super::trend::latest_confirmed_finding_ids(&records);
    eprintln!(
        "PERF latest_confirmed_finding_ids: {:?} ({} confirmed)",
        timer.elapsed(),
        confirmed.len()
    );

    let config = crate::config::V2Config::default();
    let ctx = crate::modules::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let timer = Instant::now();
    let status = execute_campaign_status(&json!({}), &ctx).unwrap();
    eprintln!(
        "PERF campaign:status (all shapes, incl store load + history): {:?}",
        timer.elapsed()
    );
    assert_eq!(status["data"]["campaigns"].as_array().unwrap().len(), 1);

    let timer = Instant::now();
    let coverage = execute_campaign_coverage(&json!({}), &ctx).unwrap();
    eprintln!("PERF campaign:coverage: {:?}", timer.elapsed());
    assert!(coverage["ok"].as_bool().unwrap_or(false));
}

/// Pure fold timings at full task-queue scale (10k findings / 30k decision
/// records), synthesized in memory: the folds are what status, coverage,
/// trend, and the backlog consume; the store write path is measured
/// separately above because the event-sourced writer dominates it.
#[test]
#[ignore = "perf baseline; run explicitly and read timings"]
fn perf_baseline_pure_folds_at_10k_30k() {
    use crate::findings::{
        ReviewDecision, ReviewDecisionRecord, ReviewDecisionVerdict, TriageAuthor,
    };
    use std::time::Instant;

    const FINDINGS: i64 = 10_000;
    let verdicts = [
        ReviewDecisionVerdict::Confirmed,
        ReviewDecisionVerdict::RejectedFalsePositive,
        ReviewDecisionVerdict::Deferred,
    ];
    let mut records = Vec::with_capacity((FINDINGS * 3) as usize);
    let mut record_id = 0i64;
    for finding_id in 0..FINDINGS {
        for round in 0..3 {
            record_id += 1;
            records.push(ReviewDecisionRecord {
                id: record_id,
                finding_id,
                identity_id: None,
                decision: ReviewDecision {
                    verdict: verdicts[((finding_id + round) % 3) as usize],
                    author: TriageAuthor::Human,
                    confidence: 1.0,
                    rationale: "perf".to_string(),
                    dismiss_reason: None,
                    actor: None,
                },
                triage_verdict: None,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                provenance: None,
            });
        }
    }

    let timer = Instant::now();
    let metrics = super::trend::trend_metrics(&records, 42.0);
    eprintln!(
        "PERF trend_metrics fold over {} records: {:?} (decided {})",
        records.len(),
        timer.elapsed(),
        metrics.decided_findings
    );

    let timer = Instant::now();
    let confirmed = super::trend::latest_confirmed_finding_ids(&records);
    eprintln!(
        "PERF latest_confirmed_finding_ids over {} records: {:?} ({} confirmed)",
        records.len(),
        timer.elapsed(),
        confirmed.len()
    );

    // Sparkline + history label over a full 90-snapshot window.
    let history: Vec<super::trend_history::TrendSnapshot> = (0..90)
        .map(|index| super::trend_history::TrendSnapshot {
            ts_ms: index,
            decided_findings: index as usize,
            confirmed_findings: (index / 2) as usize,
            rejected_false_positives: (index / 3) as usize,
            campaign_spend_usd: index as f64 * 0.5,
            provider_spend_unresolved: false,
        })
        .collect();
    let timer = Instant::now();
    let label = super::trend_history::history_strip_label(&history).unwrap();
    eprintln!(
        "PERF history_strip_label over 90 snapshots: {:?} ({} chars)",
        timer.elapsed(),
        label.len()
    );
}
