use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::findings::{Finding, FindingListFilter, FindingStore, Severity, TriageVerdict};
use crate::runtime::{AgentRuntime, ModelTier, TriageRequest};

use super::input::{optional_nonempty_string, resolve_prompt_override};
use super::ToolExecutionContext;

#[derive(Debug, Clone)]
struct TriageRunInput {
    fingerprints: Option<Vec<String>>,
    batch_size: usize,
    prompt_template: Option<String>,
    scan_id: Option<String>,
    concurrency: usize,
    cost_cap_usd: Option<f64>,
    prefilter_threshold: i64,
    stage2_tier: ModelTier,
}

impl TriageRunInput {
    fn from_tool_input(input: &Value, cwd: &Path) -> Result<Self> {
        let mut fingerprints = Vec::new();
        if let Some(fingerprint) = optional_nonempty_string(input, "fingerprint")? {
            fingerprints.push(fingerprint);
        }
        if let Some(values) = input.get("fingerprints") {
            let Value::Array(items) = values else {
                anyhow::bail!("triage:run fingerprints must be an array of strings");
            };
            for item in items {
                let Some(value) = item
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    anyhow::bail!("triage:run fingerprints entries must be non-empty strings");
                };
                fingerprints.push(value.to_string());
            }
        }

        let batch_size = match input.get("batchSize").or_else(|| input.get("batch_size")) {
            Some(Value::Number(number)) => {
                let value = number
                    .as_u64()
                    .context("triage:run batchSize must be a positive integer")?;
                if value == 0 {
                    anyhow::bail!("triage:run batchSize must be a positive integer");
                }
                value.min(500) as usize
            }
            Some(Value::String(value)) => {
                let parsed = value
                    .parse::<usize>()
                    .context("triage:run batchSize must be a positive integer")?;
                if parsed == 0 {
                    anyhow::bail!("triage:run batchSize must be a positive integer");
                }
                parsed.min(500)
            }
            Some(_) => anyhow::bail!("triage:run batchSize must be a positive integer"),
            None => 5,
        };

        let prompt_template = optional_nonempty_string(input, "TRIAGE_PROMPT")?
            .map(|value| resolve_prompt_override(&value, cwd))
            .transpose()?;
        let scan_id = optional_nonempty_string(input, "scanId")?
            .or(optional_nonempty_string(input, "scan_id")?);

        let concurrency = match input.get("concurrency") {
            Some(Value::Number(n)) => n.as_u64().unwrap_or(8).clamp(1, 64) as usize,
            None => 8,
            Some(_) => anyhow::bail!("triage:run concurrency must be a positive integer"),
        };

        let cost_cap_usd = match input
            .get("costCapUsd")
            .or_else(|| input.get("cost_cap_usd"))
        {
            Some(Value::Number(n)) => n.as_f64(),
            None => std::env::var("KUZUSHI_COST_CAP_USD")
                .ok()
                .and_then(|s| s.trim().parse::<f64>().ok()),
            Some(_) => anyhow::bail!("triage:run costCapUsd must be a number"),
        };

        let prefilter_threshold = input
            .get("prefilterThreshold")
            .or_else(|| input.get("prefilter_threshold"))
            .and_then(Value::as_i64)
            .unwrap_or(0);

        let stage2_tier = match input
            .get("stage2Tier")
            .or_else(|| input.get("stage2_tier"))
            .and_then(Value::as_str)
        {
            Some("cheap") | None => ModelTier::Cheap,
            Some("mid") => ModelTier::Mid,
            Some("deep") => ModelTier::Deep,
            Some(other) => {
                anyhow::bail!("triage:run stage2Tier must be one of cheap|mid|deep (got {other:?})")
            }
        };

        Ok(Self {
            fingerprints: if fingerprints.is_empty() {
                None
            } else {
                Some(fingerprints)
            },
            batch_size,
            prompt_template,
            scan_id,
            concurrency,
            cost_cap_usd,
            prefilter_threshold,
            stage2_tier,
        })
    }
}

fn prefilter_score(finding: &Finding) -> i64 {
    let mut score: i64 = match finding.severity {
        Severity::Critical => 8,
        Severity::High => 5,
        Severity::Medium => 3,
        Severity::Low | Severity::Info | Severity::Unknown => 1,
    };
    let msg = finding.message.to_ascii_lowercase();
    for keyword in [
        "attacker",
        "untrusted",
        "user-controlled",
        "user controlled",
        "out-of-bounds",
        "use-after-free",
        "race condition",
        "buffer overflow",
        "integer overflow",
        "memory corruption",
        "command injection",
        "sql injection",
    ] {
        if msg.contains(keyword) {
            score += 2;
        }
    }
    match finding.tool.as_str() {
        "codeql" | "cargo-audit" | "iac-scan" | "secret-scan" => score += 2,
        "semgrep" => score += 1,
        _ => {}
    }
    score
}

pub(in crate::modules) fn run_triage(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "triage:run needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("triage:run requires a findings store for the active workspace")?;

    let input = TriageRunInput::from_tool_input(&input, workspace.root())?;
    let (findings, missing_fingerprints) = select_triage_findings(store, &input)?;
    if findings.is_empty() {
        return Ok(json!({
            "ok": false,
            "output": "[-] No findings match. Run a scanner first (`kuzushi scan <repo>`) or pass explicit fingerprints.",
            "data": {
                "triaged": 0,
                "total": 0,
                "tp": 0,
                "fp": 0,
                "needsReview": 0,
                "byDesign": 0,
                "costUsd": 0.0,
                "missingFingerprints": missing_fingerprints,
                "batchSize": input.batch_size,
            },
            "costUsd": 0.0,
        }));
    }

    let runtime = runtime.context(
        "triage:run requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model_configured = ctx.config.model.clone().context(
        "triage:run requires an explicit model in config.toml or KUZUSHI_MODEL; Kuzushi will not choose a fallback model",
    )?;
    let stage2_model = runtime.model_for_tier(input.stage2_tier, &model_configured);

    let total = findings.len();
    let (kept, dropped_prefilter): (Vec<Finding>, Vec<Finding>) = findings
        .into_iter()
        .partition(|f| prefilter_score(f) >= input.prefilter_threshold);
    let stage1_kept = kept.len();
    let stage1_dropped = dropped_prefilter.len();

    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut needs_review = 0usize;
    let mut by_design = 0usize;
    let mut total_cost: f64 = 0.0;
    let mut cost_cap_hit = false;
    let mut results: Vec<Value> = Vec::with_capacity(stage1_kept);
    let mut pending_after_cap = 0usize;

    let cwd = workspace.root().to_path_buf();
    let prompt_template = input.prompt_template.clone();

    for finding in kept {
        if let Some(cap) = input.cost_cap_usd {
            if total_cost >= cap {
                cost_cap_hit = true;
                pending_after_cap += 1;
                continue;
            }
        }

        let req = TriageRequest {
            model: stage2_model.clone(),
            cwd: cwd.clone(),
            finding: finding.clone(),
            prompt_template: prompt_template.clone(),
        };
        let outcome = match runtime.triage_finding_blocking(req) {
            Ok(o) => o,
            Err(err) => {
                results.push(json!({
                    "fingerprint": finding.fingerprint,
                    "stage": "haiku",
                    "verdict": "needs_review",
                    "confidence": 0.0,
                    "rationale": format!("triage call failed: {err}"),
                }));
                needs_review += 1;
                continue;
            }
        };
        let finding_id = match finding.id {
            Some(id) => id,
            None => {
                results.push(json!({
                    "fingerprint": finding.fingerprint,
                    "stage": "haiku",
                    "verdict": outcome.verdict.as_str(),
                    "confidence": outcome.confidence,
                    "rationale": "finding lacked SQLite id; verdict not persisted",
                }));
                continue;
            }
        };
        total_cost += outcome.cost_usd;
        match outcome.verdict {
            TriageVerdict::TruePositive => tp += 1,
            TriageVerdict::FalsePositive => fp += 1,
            TriageVerdict::NeedsReview => needs_review += 1,
            TriageVerdict::ByDesign => by_design += 1,
        }
        if let Err(err) = store.save_triage(finding_id, &outcome) {
            eprintln!(
                "[triage:run] could not persist triage for finding {}: {err}",
                finding.fingerprint
            );
        }
        results.push(json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": outcome.rationale,
            "costUsd": outcome.cost_usd,
        }));
    }

    let triaged = results.len();
    let dropped_high_conf_fp = results
        .iter()
        .filter(|r| {
            r.get("verdict").and_then(Value::as_str) == Some("false_positive")
                && r.get("confidence").and_then(Value::as_f64).unwrap_or(0.0) >= 0.7
        })
        .count();

    let stages = json!([
        {
            "stage": "prefilter",
            "kept": stage1_kept,
            "dropped": stage1_dropped,
            "rule": format!("prefilter_score >= {}", input.prefilter_threshold),
        },
        {
            "stage": "haiku",
            "model": stage2_model,
            "concurrency": input.concurrency,
            "triaged": triaged,
            "tp": tp,
            "fp": fp,
            "needsReview": needs_review,
            "byDesign": by_design,
            "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
            "costUsd": total_cost,
            "costCapHit": cost_cap_hit,
            "pendingAfterCap": pending_after_cap,
        }
    ]);

    let mut summary = format!(
        "[+] Triaged {triaged} of {total} findings (stage1 dropped {stage1_dropped})\n      tp={tp}  fp={fp}  needs_review={needs_review}"
    );
    if by_design > 0 {
        summary.push_str(&format!("  by_design={by_design}"));
    }
    summary.push_str(&format!("\n      cost=${total_cost:.4}"));
    if cost_cap_hit {
        summary.push_str(&format!(
            "\n[!] cost cap hit; {pending_after_cap} finding(s) remain unevaluated"
        ));
    }
    if !missing_fingerprints.is_empty() {
        summary.push_str(&format!(
            "\n[!] {} requested finding(s) were not found",
            missing_fingerprints.len()
        ));
    }

    Ok(json!({
        "ok": true,
        "output": summary,
        "data": {
            "triaged": triaged,
            "total": total,
            "tp": tp,
            "fp": fp,
            "needsReview": needs_review,
            "byDesign": by_design,
            "costUsd": total_cost,
            "missingFingerprints": missing_fingerprints,
            "batchSize": input.batch_size,
            "concurrency": input.concurrency,
            "stage2Tier": match input.stage2_tier {
                ModelTier::Cheap => "cheap",
                ModelTier::Mid => "mid",
                ModelTier::Deep => "deep",
            },
            "costCapUsd": input.cost_cap_usd,
            "costCapHit": cost_cap_hit,
            "pendingAfterCap": pending_after_cap,
            "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
            "stages": stages,
            "results": results,
        },
        "costUsd": total_cost,
    }))
}

fn select_triage_findings(
    store: &FindingStore,
    input: &TriageRunInput,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let mut findings = Vec::new();
    let mut missing = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(fingerprints) = &input.fingerprints {
        for reference in fingerprints {
            match store.get_finding_by_reference(reference)? {
                Some(finding)
                    if input
                        .scan_id
                        .as_ref()
                        .is_none_or(|scan_id| finding.scan_id.as_deref() == Some(scan_id)) =>
                {
                    if seen.insert(finding.fingerprint.clone()) {
                        findings.push(finding);
                    }
                }
                _ => missing.push(reference.clone()),
            }
        }
    } else {
        for finding in store.list_findings(FindingListFilter::MAX_LIMIT)? {
            if input
                .scan_id
                .as_ref()
                .is_some_and(|scan_id| finding.scan_id.as_deref() != Some(scan_id))
            {
                continue;
            }
            findings.push(finding);
        }
    }

    Ok((findings, missing))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding_with(severity: Severity, tool: &str, message: &str) -> Finding {
        Finding::new_tool(tool, "rule", "src/lib.rs", 1, None, severity, message)
    }

    #[test]
    fn prefilter_score_scales_with_severity() {
        assert!(
            prefilter_score(&finding_with(Severity::Critical, "semgrep", "plain"))
                > prefilter_score(&finding_with(Severity::Low, "semgrep", "plain"))
        );
    }

    #[test]
    fn prefilter_score_bumps_for_attacker_keywords() {
        let plain = finding_with(Severity::Medium, "semgrep", "plain bug");
        let attacker = finding_with(
            Severity::Medium,
            "semgrep",
            "attacker controls SQL injection",
        );
        assert!(prefilter_score(&attacker) > prefilter_score(&plain));
    }

    #[test]
    fn prefilter_score_bumps_for_curated_tools() {
        let semgrep = finding_with(Severity::Medium, "semgrep", "plain");
        let codeql = finding_with(Severity::Medium, "codeql", "plain");
        assert!(prefilter_score(&codeql) > prefilter_score(&semgrep));
    }

    #[test]
    fn prefilter_score_unknown_severity_is_low() {
        let unknown = finding_with(Severity::Unknown, "other", "plain");
        assert_eq!(prefilter_score(&unknown), 1);
    }

    #[test]
    fn prefilter_score_is_deterministic() {
        let finding = finding_with(
            Severity::High,
            "codeql",
            "attacker controls buffer overflow",
        );
        assert_eq!(prefilter_score(&finding), prefilter_score(&finding));
    }

    #[test]
    fn triage_run_input_parses_aliases_limits_and_prompt_files() {
        let temp = tempfile::tempdir().unwrap();
        let prompt = temp.path().join("triage.md");
        std::fs::write(&prompt, "custom triage prompt").unwrap();

        let parsed = TriageRunInput::from_tool_input(
            &json!({
                "fingerprint": " fp-1 ",
                "fingerprints": ["fp-2"],
                "batch_size": "999",
                "TRIAGE_PROMPT": "./triage.md",
                "scan_id": "scan-1",
                "concurrency": 128,
                "cost_cap_usd": 1.25,
                "prefilter_threshold": 7,
                "stage2_tier": "deep"
            }),
            temp.path(),
        )
        .unwrap();

        assert_eq!(
            parsed.fingerprints,
            Some(vec!["fp-1".to_string(), "fp-2".to_string()])
        );
        assert_eq!(parsed.batch_size, 500);
        assert_eq!(
            parsed.prompt_template,
            Some("custom triage prompt".to_string())
        );
        assert_eq!(parsed.scan_id, Some("scan-1".to_string()));
        assert_eq!(parsed.concurrency, 64);
        assert_eq!(parsed.cost_cap_usd, Some(1.25));
        assert_eq!(parsed.prefilter_threshold, 7);
        assert_eq!(parsed.stage2_tier, ModelTier::Deep);
    }

    #[test]
    fn triage_run_input_rejects_invalid_shapes() {
        let cwd = Path::new(".");
        assert!(
            TriageRunInput::from_tool_input(&json!({"fingerprints": "fp"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("fingerprints must be an array")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"fingerprints": [""]}), cwd)
                .unwrap_err()
                .to_string()
                .contains("non-empty strings")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"batchSize": 0}), cwd)
                .unwrap_err()
                .to_string()
                .contains("batchSize")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"concurrency": "many"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("concurrency")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"costCapUsd": "expensive"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("costCapUsd")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"stage2Tier": "max"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("stage2Tier")
        );
    }
}
