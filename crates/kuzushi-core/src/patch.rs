use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::findings::{
    Finding, PatchAttempt, PatchResult, PatchStatus, TriageOutcome, TriageVerdict,
};
use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime};

#[derive(Debug, Clone)]
struct PatchFindingInput {
    fingerprint: String,
    max_iterations: usize,
    build_cmd: Option<String>,
    test_cmd: Option<String>,
}

impl PatchFindingInput {
    fn from_tool_input(input: &Value) -> Result<Self> {
        let fingerprint = match input.get("fingerprint") {
            Some(Value::String(value)) if !value.trim().is_empty() => value.trim().to_string(),
            Some(_) => anyhow::bail!("patch:finding fingerprint must be a non-empty string"),
            None => anyhow::bail!("patch:finding requires a fingerprint"),
        };

        let max_iterations = match input
            .get("maxIterations")
            .or_else(|| input.get("max_iterations"))
        {
            Some(Value::Number(number)) => number
                .as_u64()
                .context("patch:finding maxIterations must be a positive integer")?
                .clamp(1, 10) as usize,
            Some(Value::String(value)) => value
                .parse::<usize>()
                .context("patch:finding maxIterations must be a positive integer")?
                .clamp(1, 10),
            Some(_) => anyhow::bail!("patch:finding maxIterations must be a positive integer"),
            None => 3,
        };

        Ok(Self {
            fingerprint,
            max_iterations,
            build_cmd: optional_string_alias(input, &["buildCmd", "buildCommand"])?,
            test_cmd: optional_string_alias(input, &["testCmd", "testCommand"])?,
        })
    }
}

#[derive(Debug, Clone)]
struct PatchValidationPlan {
    build: Option<String>,
    test: Option<String>,
}

#[derive(Debug, Clone)]
struct PatchSynthesis {
    diff: String,
    explanation: String,
}

const PATCH_SYSTEM_PROMPT: &str = r#"You are Kuzushi's security patch generator.
Return only JSON matching:
{"diff":"unified diff with a/ and b/ paths","explanation":"short explanation"}."#;

pub fn run_patch_finding(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "patch:finding needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("patch:finding requires a findings store for the active workspace")?;
    let input = PatchFindingInput::from_tool_input(&input)?;
    let Some(finding) = store.get_finding_by_reference(&input.fingerprint)? else {
        return Ok(json!({
            "ok": false,
            "output": format!("[-] No finding with fingerprint '{}'.", input.fingerprint),
        }));
    };
    let Some(triage) = finding.triage.clone() else {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "[-] Finding '{}' has no triage verdict. Run triage:run first.",
                finding.fingerprint
            ),
        }));
    };
    if triage.verdict != TriageVerdict::TruePositive {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "[-] Finding '{}' is not confirmed true_positive; patch:finding only patches confirmed findings.",
                finding.fingerprint
            ),
        }));
    }

    let runtime = runtime.context(
        "patch:finding requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = ctx.config.model.clone().context(
        "patch:finding requires an explicit model in config.toml or KUZUSHI_MODEL; Kuzushi will not choose a fallback model",
    )?;

    let detected = detect_validation_plan(workspace.root());
    let plan = PatchValidationPlan {
        build: input.build_cmd.or(detected.build),
        test: input.test_cmd.or(detected.test),
    };
    let repo_name = workspace
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo")
        .to_string();
    ensure_git_repository(workspace.root())?;

    let patch_run_id = Uuid::new_v4().to_string();
    let mut history = Vec::new();
    let mut final_status = PatchStatus::Unknown;
    let mut final_diff = None;
    let mut final_explanation = None;
    let mut total_cost = 0.0f64;

    for attempt in 1..=input.max_iterations {
        let spend_ticket = match ctx.spend {
            Some(limiter) => match limiter.deposit(
                crate::spend::Operation::Patch,
                crate::spend::estimate_deposit_usd(crate::spend::Operation::Patch, &model),
            ) {
                Ok(ticket) => Some(ticket),
                Err(error) => {
                    eprintln!(
                        "[warn] patch budget exceeded for {}: {error}",
                        finding.fingerprint
                    );
                    break;
                }
            },
            None => None,
        };
        let synthesis = synthesize_patch(
            runtime,
            &model,
            workspace.root(),
            &repo_name,
            &finding,
            &triage,
            &history,
        )?;
        if let Some(ticket) = spend_ticket {
            let estimate = ticket.est_usd();
            if let Some(limiter) = ctx.spend {
                let _ = limiter.refund(ticket, estimate);
            }
            total_cost += estimate;
        }
        let worktree = create_disposable_worktree(workspace.root())?;
        let validation = validate_patch(&worktree, &synthesis.diff, &plan);
        cleanup_worktree(workspace.root(), &worktree);

        history.push(PatchAttempt {
            attempt,
            diff: synthesis.diff.clone(),
            status: validation.status,
            output: validation.output.clone(),
        });
        final_status = validation.status;
        final_diff = Some(synthesis.diff);
        final_explanation = Some(synthesis.explanation);
        if validation.status == PatchStatus::Sound {
            break;
        }
    }

    let validator_log = history
        .iter()
        .map(|attempt| {
            format!(
                "[Attempt {}] {}: {}",
                attempt.attempt,
                attempt.status.as_str(),
                attempt.output
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");

    let result = PatchResult {
        patch_run_id,
        fingerprint: finding.fingerprint.clone(),
        repo: repo_name,
        diff: final_diff,
        status: final_status,
        iterations: history.len(),
        build_command: plan.build.clone(),
        test_command: plan.test.clone(),
        worktree_path: None,
        cost_usd: Some(total_cost),
        validator_log: Some(validator_log.clone()),
        history,
        created_at: None,
        updated_at: None,
    };
    store.insert_patch_result(&result)?;
    let history_run_id = finding.scan_id.as_deref().unwrap_or("patch");
    if let Err(error) = store.record_analysis(
        &finding.fingerprint,
        history_run_id,
        "patch",
        &model,
        result.cost_usd.unwrap_or(0.0),
        &crate::findings::RefusalReport::default(),
    ) {
        eprintln!(
            "[warn] could not record analysis history for {}: {error}",
            finding.fingerprint
        );
    }

    Ok(patch_result_to_tool_json(
        &finding.fingerprint,
        &result,
        &validator_log,
        final_explanation.as_deref(),
    ))
}

fn patch_result_to_tool_json(
    fingerprint: &str,
    result: &PatchResult,
    validator_log: &str,
    explanation: Option<&str>,
) -> Value {
    let sound = result.status == PatchStatus::Sound;
    let mut lines = vec![
        format!(
            "[{}] patch:finding {}",
            if sound { "+" } else { "!" },
            result.status.as_str()
        ),
        format!("      fingerprint:   {fingerprint}"),
        format!("      iterations:    {}", result.iterations),
        "      cost:          $0.0000".to_string(),
    ];

    if sound {
        if let Some(diff) = result
            .diff
            .as_ref()
            .filter(|value| !value.trim().is_empty())
        {
            lines.push(String::new());
            lines.push("Diff:".to_string());
            lines.push(diff.to_string());
        }
    } else if !validator_log.trim().is_empty() {
        lines.push(String::new());
        lines.push("Validator log:".to_string());
        lines.push(validator_log.to_string());
    }

    json!({
        "ok": sound,
        "output": lines.join("\n"),
        "data": {
            "status": result.status.as_str(),
            "iterations": result.iterations,
            "patchRunId": result.patch_run_id,
            "diff": result.diff,
            "costUsd": 0.0,
            "validatorLog": result.validator_log,
            "history": result.history,
            "buildCommand": result.build_command,
            "testCommand": result.test_command,
            "worktreePath": result.worktree_path,
            "explanation": explanation,
        },
        "costUsd": 0.0,
    })
}

fn synthesize_patch(
    runtime: &dyn AgentRuntime,
    model: &str,
    repo_root: &Path,
    repo_name: &str,
    finding: &Finding,
    triage: &TriageOutcome,
    history: &[PatchAttempt],
) -> Result<PatchSynthesis> {
    let prompt = build_patch_prompt(repo_root, repo_name, finding, triage, history)?;
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model.to_string(),
        repo_root.to_path_buf(),
        PATCH_SYSTEM_PROMPT.to_string(),
        prompt,
    ))?;
    let raw = match response.structured {
        Some(value) => value,
        None => parse_json_object_from_agent_text(&response.text)
            .context("patch:finding expected pi-agent-core to return JSON with diff/explanation")?,
    };
    parse_patch_synthesis(raw)
}

fn build_patch_prompt(
    repo_root: &Path,
    repo_name: &str,
    finding: &Finding,
    triage: &TriageOutcome,
    history: &[PatchAttempt],
) -> Result<String> {
    let finding_json =
        serde_json::to_string_pretty(finding).context("Could not serialize finding")?;
    let triage_json = serde_json::to_string_pretty(triage).context("Could not serialize triage")?;
    let source_context = read_source_context(repo_root, &finding.file_path)?;
    let history_block = if history.is_empty() {
        "No previous patch attempts.".to_string()
    } else {
        history
            .iter()
            .map(|attempt| {
                format!(
                    "### Attempt {} - {}\nDiff:\n```diff\n{}\n```\nValidator output:\n{}",
                    attempt.attempt,
                    attempt.status.as_str(),
                    attempt.diff,
                    attempt.output
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    };

    Ok(format!(
        "Generate a minimal unified diff that fixes this confirmed security finding.\n\
         The diff must apply with `git apply` from the repository root and use a/ and b/ paths.\n\n\
         ## Repository\n{repo_name}\n\n\
         ## Finding JSON\n{finding_json}\n\n\
         ## Triage JSON\n{triage_json}\n\n\
         ## Vulnerable Source Context\n{source_context}\n\n\
         ## Previous Attempts\n{history_block}\n\n\
         ## Output\nReturn only a JSON object with string fields `diff` and `explanation`."
    ))
}

fn read_source_context(repo_root: &Path, file_path: &str) -> Result<String> {
    let path = repo_root.join(file_path);
    let Ok(raw) = fs::read_to_string(&path) else {
        return Ok(format!(
            "Could not read {}; produce a patch from the finding metadata.",
            file_path
        ));
    };
    let max_bytes = 40_000usize;
    let content = if raw.len() > max_bytes {
        let cutoff = raw
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index <= max_bytes)
            .last()
            .unwrap_or(0);
        format!("{}\n... [truncated]", &raw[..cutoff])
    } else {
        raw
    };
    Ok(format!("File: {file_path}\n```text\n{content}\n```"))
}

fn parse_patch_synthesis(raw: Value) -> Result<PatchSynthesis> {
    let Value::Object(object) = raw else {
        anyhow::bail!("patch synthesis output parse failed: expected a JSON object");
    };
    let diff = read_object_raw_string(&object, &["diff"])
        .context("patch synthesis output parse failed: missing non-empty diff")?;
    let explanation = read_object_string(&object, &["explanation"]).unwrap_or_default();
    Ok(PatchSynthesis { diff, explanation })
}

fn parse_json_object_from_agent_text(text: &str) -> Result<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return Ok(value);
    }

    let start = text
        .find('{')
        .context("patch output parse failed: missing JSON object start")?;
    let end = text
        .rfind('}')
        .context("patch output parse failed: missing JSON object end")?;
    if end < start {
        anyhow::bail!("patch output parse failed: malformed JSON object");
    }

    serde_json::from_str(&text[start..=end])
        .with_context(|| "patch output parse failed: invalid JSON object")
}

#[derive(Debug, Clone)]
struct ValidationResult {
    status: PatchStatus,
    output: String,
}

fn validate_patch(
    worktree_path: &Path,
    diff: &str,
    plan: &PatchValidationPlan,
) -> ValidationResult {
    let mut logs = Vec::new();

    match run_git_with_input(worktree_path, &["apply", "--check"], diff) {
        Ok(_) => logs.push("git apply --check: OK".to_string()),
        Err(error) => {
            logs.push(format!("git apply --check: FAILED - {error}"));
            return ValidationResult {
                status: PatchStatus::ApplyFailed,
                output: logs.join("\n"),
            };
        }
    }

    match run_git_with_input(worktree_path, &["apply"], diff) {
        Ok(_) => logs.push("git apply: OK".to_string()),
        Err(error) => {
            logs.push(format!("git apply: FAILED - {error}"));
            return ValidationResult {
                status: PatchStatus::ApplyFailed,
                output: logs.join("\n"),
            };
        }
    }

    if let Some(command) = &plan.build {
        match run_shell_command(worktree_path, command) {
            Ok(_) => logs.push(format!("build ({command}): OK")),
            Err(error) => {
                logs.push(format!("build ({command}): FAILED - {error}"));
                return ValidationResult {
                    status: PatchStatus::BuildFailed,
                    output: logs.join("\n"),
                };
            }
        }
    }

    if let Some(command) = &plan.test {
        match run_shell_command(worktree_path, command) {
            Ok(_) => logs.push(format!("tests ({command}): OK")),
            Err(error) => {
                logs.push(format!("tests ({command}): FAILED - {error}"));
                return ValidationResult {
                    status: PatchStatus::TestsFailed,
                    output: logs.join("\n"),
                };
            }
        }
    }

    logs.push("All validations passed.".to_string());
    ValidationResult {
        status: PatchStatus::Sound,
        output: logs.join("\n"),
    }
}

fn ensure_git_repository(repo_root: &Path) -> Result<()> {
    let output = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(repo_root)
        .output()
        .with_context(|| "patch:finding could not start git; install Git and retry")?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "true" {
        anyhow::bail!(
            "patch:finding requires a git repository target; initialize git or pass --target <repo>"
        );
    }
    Ok(())
}

fn create_disposable_worktree(repo_root: &Path) -> Result<PathBuf> {
    let worktree_base = repo_root.join(".kuzushi").join("worktrees");
    fs::create_dir_all(&worktree_base)
        .with_context(|| format!("Could not create {}", worktree_base.display()))?;
    let worktree_path = worktree_base.join(Uuid::new_v4().to_string());
    let output = Command::new("git")
        .args([
            "worktree",
            "add",
            "--detach",
            &worktree_path.display().to_string(),
            "HEAD",
        ])
        .current_dir(repo_root)
        .output()
        .with_context(|| "patch:finding could not create disposable git worktree")?;
    if !output.status.success() {
        anyhow::bail!(
            "patch:finding could not create disposable git worktree: {}",
            command_output_text(&output)
        );
    }
    Ok(worktree_path)
}

fn cleanup_worktree(repo_root: &Path, worktree_path: &Path) {
    let _ = Command::new("git")
        .args([
            "worktree",
            "remove",
            "--force",
            &worktree_path.display().to_string(),
        ])
        .current_dir(repo_root)
        .output();
}

fn run_git_with_input(cwd: &Path, args: &[&str], input: &str) -> Result<String> {
    let mut child = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| "patch:finding could not start git; install Git and retry")?;
    child
        .stdin
        .as_mut()
        .context("patch:finding could not open git stdin")?
        .write_all(input.as_bytes())?;
    let output = child
        .wait_with_output()
        .context("patch:finding could not read git output")?;
    if !output.status.success() {
        anyhow::bail!("{}", command_output_text(&output));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_shell_command(cwd: &Path, command: &str) -> Result<String> {
    let output = Command::new("sh")
        .args(["-lc", command])
        .current_dir(cwd)
        .output()
        .with_context(|| format!("patch:finding could not start validation command {command:?}"))?;
    if !output.status.success() {
        anyhow::bail!("{}", command_output_text(&output));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn command_output_text(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    [stderr, stdout]
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn detect_validation_plan(repo_root: &Path) -> PatchValidationPlan {
    if repo_root.join("package.json").exists() {
        return PatchValidationPlan {
            build: Some("npm run build".to_string()),
            test: Some("npm test".to_string()),
        };
    }
    if repo_root.join("Makefile").exists() {
        return PatchValidationPlan {
            build: Some("make".to_string()),
            test: Some("make test".to_string()),
        };
    }
    if repo_root.join("Cargo.toml").exists() {
        return PatchValidationPlan {
            build: Some("cargo build".to_string()),
            test: Some("cargo test".to_string()),
        };
    }
    if repo_root.join("setup.py").exists() || repo_root.join("pyproject.toml").exists() {
        return PatchValidationPlan {
            build: None,
            test: Some("python -m pytest".to_string()),
        };
    }
    if repo_root.join("go.mod").exists() {
        return PatchValidationPlan {
            build: Some("go build ./...".to_string()),
            test: Some("go test ./...".to_string()),
        };
    }
    PatchValidationPlan {
        build: None,
        test: None,
    }
}

fn optional_string_alias(input: &Value, keys: &[&str]) -> Result<Option<String>> {
    for key in keys {
        match input.get(*key) {
            Some(Value::String(value)) => {
                return Ok(Some(value.trim().to_string()).filter(|value| !value.is_empty()));
            }
            Some(_) => anyhow::bail!("patch:finding {key} must be a string"),
            None => {}
        }
    }
    Ok(None)
}

fn read_object_value<'a>(object: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

fn read_object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn read_object_raw_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
}
