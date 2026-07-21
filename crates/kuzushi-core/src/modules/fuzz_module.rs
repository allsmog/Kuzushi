use super::*;
use crate::capabilities::fuzz_engine::{
    author, bootstrap, derived_workspace_root, engine_cli, import, rounds, FuzzPaths,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DEFAULT_FUZZ_RUN_TIMEOUT_MS: u64 = 60 * 60 * 1000;
const MAX_FUZZ_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;
const WORKSPACE_INIT_TIMEOUT: Duration = Duration::from_secs(300);
const SINK_SCAN_TIMEOUT: Duration = Duration::from_secs(1800);
const GENERATE_TIMEOUT: Duration = Duration::from_secs(1800);

pub(in crate::modules) fn fuzz_module() -> BuiltinModule {
    builtin_module(
        "fuzz",
        "Fuzzing (agentic-fuzz-engine)",
        ModuleKind::Scan,
        "Drive the external agentic-fuzz-engine as a scan-phase capability: bootstrap an \
         engine workspace outside the repo, run bounded libFuzzer/SymCC/KLEE rounds, author \
         harnesses for parked workorders through the model runtime, and import verified \
         crashes into the findings store.",
        vec![
            tool_with_options(
                "fuzz:run",
                "Bootstrap the engine workspace (init, sink scan, deterministic generation, \
                 builds) as needed, run bounded fuzz campaign rounds, and import verified \
                 crashes. Returns an explicit skipped result when the engine checkout is not \
                 configured.",
                fuzz_run_options(),
            )
            .with_policy(repository_execute_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            )),
            tool_with_options(
                "fuzz:author",
                "Author harnesses for the engine's parked workorders through a Rust-driven \
                 model tool loop: the model reads sources and workorders, writes harness/build \
                 files under hard containment, and iterates the compile/smoke tools; a \
                 deterministic verdict grades each target.",
                fuzz_author_options(),
            )
            .with_policy(repository_execute_policy(
                ToolPhase::Map,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Required,
            )),
            tool_with_options(
                "fuzz:import",
                "Import the engine's verified crash ledger (findings-index.jsonl) into the \
                 findings store with impact-derived severity, without running the engine.",
                fuzz_import_options(),
            )
            .with_policy(workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            )),
            tool_with_options(
                "fuzz:status",
                "Probe the engine workspace: bootstrap state, targets, built fuzzers, parked \
                 workorders, and verified finding counts. Read-only, no engine invocation.",
                fuzz_status_options(),
            )
            .with_policy(read_policy(ToolPhase::Scan, WorkspaceRequirement::Required)),
        ],
        vec![dag("fuzz:run", "fuzz", &[])],
    )
}

fn shared_engine_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        opt(
            "afeRepo",
            OptionType::Path,
            "agentic-fuzz-engine checkout (must contain src/agentic_fuzz_engine/cli.py). \
             When omitted, the tool returns an explicit skipped result.",
        )
        .external_read()
        .aliases(&["afe_repo"]),
        opt(
            "pythonBin",
            OptionType::Path,
            "Python interpreter for the engine. Defaults to the engine repo's .venv, then \
             python3 on PATH.",
        )
        .executable()
        .aliases(&["python_bin"])
        .advanced(),
        opt(
            "workspaceRoot",
            OptionType::Path,
            "Engine workspace directory (holds targets, corpus, binaries). Must live OUTSIDE \
             the scanned repository; defaults to a per-target directory under \
             ~/.cache/agentic-fuzz/kuzushi/.",
        )
        .external_write()
        .aliases(&["workspace_root"]),
        opt(
            "dataRoot",
            OptionType::Path,
            "Engine state root (runs, findings index). Defaults to <workspaceRoot>/data.",
        )
        .external_write()
        .aliases(&["data_root"])
        .advanced(),
        opt(
            "afeTarget",
            OptionType::String,
            "Restrict to one engine target name. Campaign plan rows map their shard name here.",
        )
        .aliases(&["afe_target", "shard"]),
        opt(
            "paths",
            OptionType::StringList,
            "Accepted for campaign job compatibility and recorded; fuzzing scope is the \
             engine target, not a path list.",
        )
        .advanced(),
    ]
}

fn fuzz_run_options() -> Vec<OptionSpec> {
    let mut options = shared_engine_options();
    options.extend(vec![
        opt(
            "generatorSpec",
            OptionType::String,
            "Generator spec (name under <workspaceRoot>/generators/ or a JSON file path) for \
             deterministic target generation when no targets exist yet. Only type_enum, \
             direct_call, and symbolic_string specs are accepted.",
        )
        .aliases(&["generator_spec"]),
        opt("rounds", OptionType::Int, "Campaign rounds per target.")
            .integer_range(1, 24)
            .default(json!(1)),
        opt(
            "fuzzSeconds",
            OptionType::Int,
            "Fuzz-lane seconds per round (SymCC sync and periodic KLEE add engine-side slack).",
        )
        .aliases(&["fuzz_seconds"])
        .integer_range(30, 21_600)
        .default(json!(600)),
        opt("rssLimitMb", OptionType::Int, "libFuzzer RSS limit per run.")
            .aliases(&["rss_limit_mb"])
            .default(json!(2048))
            .advanced(),
        opt(
            "minFreeGb",
            OptionType::Int,
            "Engine disk-headroom guard: rounds refuse to start below this free space.",
        )
        .aliases(&["min_free_gb"])
        .default(json!(10))
        .advanced(),
        opt(
            "maxGeneratedTargets",
            OptionType::Int,
            "Cap on deterministically generated targets per run.",
        )
        .aliases(&["max_generated_targets"])
        .integer_range(1, 50)
        .default(json!(5))
        .advanced(),
        opt(
            "buildTimeoutMs",
            OptionType::Int,
            "Per-target engine build deadline.",
        )
        .aliases(&["build_timeout_ms"])
        .default(json!(900_000))
        .advanced(),
        opt(
            "skipImport",
            OptionType::Bool,
            "Run rounds without importing findings afterwards.",
        )
        .aliases(&["skip_import"])
        .default(json!(false))
        .advanced(),
        fuzz_timeout_option(),
    ]);
    options
}

fn fuzz_author_options() -> Vec<OptionSpec> {
    let mut options = shared_engine_options();
    options.extend(vec![
        model_option(),
        opt(
            "budgetUsd",
            OptionType::Float,
            "Model-spend ceiling across all authoring sessions in this run.",
        )
        .aliases(&["budget_usd"])
        .default(json!(5.0)),
        opt(
            "maxTargets",
            OptionType::Int,
            "How many parked workorders to attempt this run.",
        )
        .aliases(&["max_targets"])
        .integer_range(1, 12)
        .default(json!(3)),
        opt(
            "maxSteps",
            OptionType::Int,
            "Model round-trip cap per authoring session.",
        )
        .aliases(&["max_steps"])
        .integer_range(4, 64)
        .default(json!(24)),
        opt(
            "smokeSeconds",
            OptionType::Int,
            "Bounded fuzzer smoke-run length used to grade an authored harness.",
        )
        .aliases(&["smoke_seconds"])
        .integer_range(5, 300)
        .default(json!(30))
        .advanced(),
        opt(
            "buildTimeoutMs",
            OptionType::Int,
            "Per-build deadline inside the authoring loop.",
        )
        .aliases(&["build_timeout_ms"])
        .default(json!(900_000))
        .advanced(),
        fuzz_timeout_option(),
    ]);
    options
}

fn fuzz_import_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        opt(
            "dataRoot",
            OptionType::Path,
            "Engine state root containing findings-index.jsonl. Defaults to the derived \
             per-target workspace's data directory.",
        )
        .external_read()
        .aliases(&["data_root"]),
        opt(
            "afeTarget",
            OptionType::String,
            "Only import findings recorded for this engine target.",
        )
        .aliases(&["afe_target", "shard"]),
        opt(
            "includeUnverified",
            OptionType::Bool,
            "Also import crashes the engine grader did not reproduce (reduced confidence; \
             severity still capped).",
        )
        .aliases(&["include_unverified"])
        .default(json!(false))
        .advanced(),
    ]
}

fn fuzz_status_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        opt(
            "workspaceRoot",
            OptionType::String,
            "Engine workspace to probe; may not exist yet (reported as uninitialized). \
             Defaults to the derived per-target workspace.",
        )
        .aliases(&["workspace_root"]),
        opt(
            "dataRoot",
            OptionType::String,
            "Engine state root to probe. Defaults to <workspaceRoot>/data.",
        )
        .aliases(&["data_root"])
        .advanced(),
    ]
}

fn fuzz_timeout_option() -> OptionSpec {
    opt(
        "timeoutMs",
        OptionType::Int,
        "Whole-tool deadline. Engine subprocess trees are killed and reaped past it.",
    )
    .aliases(&["timeout_ms"])
    .default(json!(DEFAULT_FUZZ_RUN_TIMEOUT_MS))
    .advanced()
}

// ---------------------------------------------------------------------------
// Shared path resolution
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum FuzzReadiness {
    Ready(FuzzPaths),
    Skip(String),
}

fn prepare_fuzz_paths(
    input: &Value,
    target: &Path,
) -> Result<FuzzReadiness> {
    let Some(afe_repo) = optional_string_input(input, &["afeRepo", "afe_repo"])? else {
        return Ok(FuzzReadiness::Skip(
            "no afeRepo option was provided — pass the agentic-fuzz-engine checkout path \
             to enable fuzzing"
                .to_string(),
        ));
    };
    let afe_repo = PathBuf::from(afe_repo);
    anyhow::ensure!(
        engine_cli::afe_repo_is_valid(&afe_repo),
        "afeRepo {} is not an agentic-fuzz-engine checkout (missing src/agentic_fuzz_engine/cli.py)",
        afe_repo.display()
    );
    let explicit_python =
        optional_string_input(input, &["pythonBin", "python_bin"])?.map(PathBuf::from);
    let Some(python_bin) = engine_cli::locate_python(&afe_repo, explicit_python.as_deref())
    else {
        return Ok(FuzzReadiness::Skip(
            "no usable Python interpreter (engine venv or python3 on PATH) was found".to_string(),
        ));
    };
    let workspace_root = resolve_engine_workspace_root(input, target)?;
    let data_root = resolve_engine_data_root(input, &workspace_root, target)?;
    Ok(FuzzReadiness::Ready(FuzzPaths {
        afe_repo,
        python_bin,
        workspace_root,
        data_root,
        source_dir: target.to_path_buf(),
    }))
}

fn resolve_engine_workspace_root(input: &Value, target: &Path) -> Result<PathBuf> {
    match optional_string_input(input, &["workspaceRoot", "workspace_root"])? {
        Some(value) => {
            let path = PathBuf::from(value);
            ensure_outside_target("workspaceRoot", &path, target)?;
            Ok(path)
        }
        None => Ok(derived_workspace_root(&home_dir()?, target)),
    }
}

fn resolve_engine_data_root(
    input: &Value,
    workspace_root: &Path,
    target: &Path,
) -> Result<PathBuf> {
    match optional_string_input(input, &["dataRoot", "data_root"])? {
        Some(value) => {
            let path = PathBuf::from(value);
            ensure_outside_target("dataRoot", &path, target)?;
            Ok(path)
        }
        None => Ok(FuzzPaths::data_root_for(workspace_root)),
    }
}

/// The engine workspace holds gigabytes of corpus and build state; the
/// scanned repository stays read-only, so nothing engine-owned may live
/// under it (including `.kuzushi`).
fn ensure_outside_target(option: &str, path: &Path, target: &Path) -> Result<()> {
    let canonical_target = target.canonicalize().unwrap_or_else(|_| target.to_path_buf());
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    anyhow::ensure!(
        !canonical_path.starts_with(&canonical_target) && !path.starts_with(target),
        "{option} {} must live outside the scanned repository {}",
        path.display(),
        target.display()
    );
    Ok(())
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is unset; pass workspaceRoot explicitly")
}

fn fuzz_skipped_response(tool: &str, target: &Path, reason: &str) -> Value {
    let output = format!("{tool} skipped — {reason}.");
    crate::module_result::skipped_output_result(
        output.clone(),
        output.clone(),
        vec![json!(output)],
        json!({
            "target": target.display().to_string(),
            "skipped": true,
            "reason": reason,
        }),
    )
}

// ---------------------------------------------------------------------------
// fuzz:run
// ---------------------------------------------------------------------------

struct FuzzRunOptions {
    generator_spec: Option<String>,
    rounds: u64,
    fuzz_seconds: u64,
    rss_limit_mb: u64,
    min_free_gb: u64,
    max_generated_targets: u64,
    build_timeout: Duration,
    skip_import: bool,
    afe_target: Option<String>,
}

impl FuzzRunOptions {
    fn parse(input: &Value) -> Result<Self> {
        Ok(Self {
            generator_spec: optional_string_input(input, &["generatorSpec", "generator_spec"])?,
            rounds: u64_input(input, &["rounds"], 1),
            fuzz_seconds: u64_input(input, &["fuzzSeconds", "fuzz_seconds"], 600),
            rss_limit_mb: u64_input(input, &["rssLimitMb", "rss_limit_mb"], 2048),
            min_free_gb: u64_input(input, &["minFreeGb", "min_free_gb"], 10),
            max_generated_targets: u64_input(
                input,
                &["maxGeneratedTargets", "max_generated_targets"],
                5,
            ),
            build_timeout: Duration::from_millis(u64_input(
                input,
                &["buildTimeoutMs", "build_timeout_ms"],
                900_000,
            )),
            skip_import: bool_input(input, &["skipImport", "skip_import"]),
            afe_target: optional_string_input(input, &["afeTarget", "afe_target", "shard"])?,
        })
    }
}

fn u64_input(input: &Value, keys: &[&str], default: u64) -> u64 {
    keys.iter()
        .filter_map(|key| input.get(*key))
        .find_map(Value::as_u64)
        .unwrap_or(default)
}

fn bool_input(input: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .filter_map(|key| input.get(*key))
        .find_map(Value::as_bool)
        .unwrap_or(false)
}

struct EngineRun<'a> {
    ctx: &'a ToolExecutionContext<'a>,
    paths: &'a FuzzPaths,
    deadline: Instant,
    steps: Vec<Value>,
    failed: bool,
}

impl EngineRun<'_> {
    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Run one engine verb under the step + whole-tool deadline; record the
    /// step outcome and fold `ok:false` blockers into run state.
    fn engine_step(&mut self, label: &str, args: Vec<String>, step_timeout: Duration) -> Option<Value> {
        let timeout = step_timeout.min(self.remaining());
        if timeout < Duration::from_secs(30) {
            self.record(label, "failed", json!("whole-tool deadline reached"));
            self.failed = true;
            return None;
        }
        emit_step(self.ctx, "tool", "run", format!("fuzz:run {label}"));
        match self.invoke(label, args, timeout) {
            Ok(payload) if engine_cli::engine_ok(&payload) => {
                self.record(label, "ran", json!(null));
                Some(payload)
            }
            Ok(payload) => {
                let blockers = engine_cli::engine_blockers(&payload);
                self.record(label, "failed", json!(blockers));
                self.failed = true;
                None
            }
            Err(error) => {
                self.record(label, "failed", json!(format!("{error:#}")));
                self.failed = true;
                None
            }
        }
    }

    fn invoke(&self, label: &str, args: Vec<String>, timeout: Duration) -> Result<Value> {
        let invocation = engine_cli::engine_invocation(self.paths, &args);
        let mut command = engine_cli::engine_command(&invocation);
        let output = crate::bounded_subprocess::output_with_control(
            &mut command,
            label,
            self.ctx.cancellation,
            timeout,
        )?;
        anyhow::ensure!(
            output.status.success() || !output.stdout.is_empty(),
            "engine {label} exited with {:?}: {}",
            output.status.code(),
            crate::module_result::subprocess_failure_summary(
                &output.stderr,
                "check the afeRepo checkout and its venv",
            )
        );
        engine_cli::parse_engine_json(&output.stdout)
    }

    fn record(&mut self, step: &str, status: &str, detail: Value) {
        self.steps.push(json!({
            "step": step,
            "status": status,
            "detail": detail,
        }));
    }

    fn record_skip(&mut self, step: &str, reason: &str) {
        self.steps.push(json!({
            "step": step,
            "status": "skipped",
            "detail": reason,
        }));
    }
}

pub(in crate::modules) fn run_fuzz_run(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    let paths = match prepare_fuzz_paths(input, &target)? {
        FuzzReadiness::Ready(paths) => paths,
        FuzzReadiness::Skip(reason) => {
            return Ok(fuzz_skipped_response("fuzz:run", &target, &reason))
        }
    };
    let options = FuzzRunOptions::parse(input)?;
    validate_generator_spec(&paths, options.generator_spec.as_deref())?;
    let timeout = fuzz_tool_timeout(input, "fuzz:run")?;
    let mut run = EngineRun {
        ctx,
        paths: &paths,
        deadline: Instant::now() + timeout,
        steps: Vec::new(),
        failed: false,
    };
    execute_bootstrap(&mut run, &options);
    let probe = bootstrap::probe_workspace(&paths.workspace_root);
    let selected = selected_targets(&probe, options.afe_target.as_deref());
    let summaries = execute_rounds(&mut run, &options, &selected, timeout)?;
    let import_summary = execute_import(&mut run, input, &options)?;
    Ok(fuzz_run_response(&target, &paths, run, &probe, &selected, summaries, import_summary))
}

/// Only the three deterministic generator families may drive generation;
/// agent-shaped `sequence` specs go through fuzz:author instead.
fn validate_generator_spec(paths: &FuzzPaths, spec: Option<&str>) -> Result<()> {
    let Some(spec) = spec else { return Ok(()) };
    let spec_path = if spec.ends_with(".json") {
        PathBuf::from(spec)
    } else {
        paths.workspace_root.join("generators").join(format!("{spec}.json"))
    };
    let Ok(body) = crate::bounded_file::read_utf8_text(&spec_path, 1024 * 1024) else {
        return Ok(()); // Unreadable now (workspace not yet initialized) — the engine validates.
    };
    let value: Value = serde_json::from_str(&body)
        .with_context(|| format!("generator spec {} is malformed JSON", spec_path.display()))?;
    let kind = ["type", "generator", "kind"]
        .iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .unwrap_or_default();
    anyhow::ensure!(
        kind != "sequence",
        "generator spec {} is a `sequence` spec; only type_enum/direct_call/symbolic_string \
         run deterministically — use fuzz:author for the rest",
        spec_path.display()
    );
    Ok(())
}

fn execute_bootstrap(run: &mut EngineRun<'_>, options: &FuzzRunOptions) {
    let probe = bootstrap::probe_workspace(&run.paths.workspace_root);
    let plan = bootstrap::plan_bootstrap(&probe, options.generator_spec.is_some());
    if plan.is_empty() {
        run.record_skip("bootstrap", "workspace already bootstrapped");
        return;
    }
    for step in plan {
        if run.failed {
            return;
        }
        execute_bootstrap_step(run, options, &step);
    }
}

fn execute_bootstrap_step(
    run: &mut EngineRun<'_>,
    options: &FuzzRunOptions,
    step: &bootstrap::BootstrapStep,
) {
    let ws = run.paths.workspace_root.display().to_string();
    let src = run.paths.source_dir.display().to_string();
    match step {
        bootstrap::BootstrapStep::WorkspaceInit => {
            let args = vec!["workspace-init".into(), "--root".into(), ws, "--source-dir".into(), src];
            run.engine_step("workspace-init", args, WORKSPACE_INIT_TIMEOUT);
        }
        bootstrap::BootstrapStep::SinkScan => {
            let out = run.paths.workspace_root.join(bootstrap::SINKS_FILE);
            let args = vec![
                "sink-scan".into(),
                "--source-root".into(),
                src,
                "--out".into(),
                out.display().to_string(),
                "--workspace-root".into(),
                ws,
            ];
            run.engine_step("sink-scan", args, SINK_SCAN_TIMEOUT);
        }
        bootstrap::BootstrapStep::Generate => {
            let Some(spec) = options.generator_spec.as_deref() else { return };
            let sinks = run.paths.workspace_root.join(bootstrap::SINKS_FILE);
            let args = vec![
                "target-generate".into(),
                "--spec".into(),
                spec.to_string(),
                "--all".into(),
                "--validate".into(),
                "--sinks-jsonl".into(),
                sinks.display().to_string(),
                "--max-targets".into(),
                options.max_generated_targets.to_string(),
                "--workspace-root".into(),
                ws,
            ];
            run.engine_step("target-generate", args, GENERATE_TIMEOUT);
        }
        bootstrap::BootstrapStep::Build(target) => {
            let args = vec![
                "target-build".into(),
                target.clone(),
                "--timeout-seconds".into(),
                run_build_seconds(options).to_string(),
                "--workspace-root".into(),
                ws,
            ];
            run.engine_step(
                &format!("target-build {target}"),
                args,
                options.build_timeout + Duration::from_secs(60),
            );
        }
    }
}

fn run_build_seconds(options: &FuzzRunOptions) -> u64 {
    options.build_timeout.as_secs().max(1)
}

fn selected_targets(probe: &bootstrap::WorkspaceProbe, filter: Option<&str>) -> Vec<String> {
    probe
        .built
        .iter()
        .filter(|target| filter.is_none_or(|name| name == target.as_str()))
        .cloned()
        .collect()
}

fn execute_rounds(
    run: &mut EngineRun<'_>,
    options: &FuzzRunOptions,
    selected: &[String],
    timeout: Duration,
) -> Result<Vec<Value>> {
    if selected.is_empty() {
        run.record_skip("campaign-rounds", "no built targets to fuzz");
        return Ok(Vec::new());
    }
    rounds::round_budget(options.rounds, options.fuzz_seconds, selected.len() as u64, timeout)?;
    let mut summaries = Vec::new();
    for target in selected {
        if run.failed {
            break;
        }
        if let Some(summary) = execute_round_for(run, options, target) {
            summaries.push(summary);
        }
    }
    Ok(summaries)
}

fn execute_round_for(
    run: &mut EngineRun<'_>,
    options: &FuzzRunOptions,
    target: &str,
) -> Option<Value> {
    let ws = run.paths.workspace_root.display().to_string();
    let args = vec![
        "campaign-round-run".into(),
        target.to_string(),
        "--rounds".into(),
        options.rounds.to_string(),
        "--fuzz-seconds".into(),
        options.fuzz_seconds.to_string(),
        "--rss-limit-mb".into(),
        options.rss_limit_mb.to_string(),
        "--min-free-gb".into(),
        options.min_free_gb.to_string(),
        "--workspace-root".into(),
        ws,
    ];
    let payload = run.engine_step(&format!("campaign-round-run {target}"), args, run.remaining())?;
    let summary = rounds::parse_round_summary(&payload);
    Some(json!({
        "target": target,
        "roundsCompleted": summary.rounds_completed,
        "findingsRecorded": summary.findings_recorded,
        "diskFreeGb": summary.disk_free_gb,
        "blockers": summary.blockers,
    }))
}

fn execute_import(
    run: &mut EngineRun<'_>,
    input: &Value,
    options: &FuzzRunOptions,
) -> Result<Option<import::FuzzImportSummary>> {
    if options.skip_import {
        run.record_skip("import", "skipImport requested");
        return Ok(None);
    }
    let Some(workspace) = run.ctx.workspace else {
        run.record("import", "failed", json!("no active workspace for the findings store"));
        return Ok(None);
    };
    let filter = optional_string_input(input, &["afeTarget", "afe_target", "shard"])?;
    let request = import::FuzzImportRequest {
        data_root: &run.paths.data_root,
        source_dir: &run.paths.source_dir,
        target_filter: filter.as_deref(),
        include_unverified: false,
    };
    match import::import_afe_findings(workspace, &request) {
        Ok(summary) => {
            run.record("import", "ran", json!(summary.imported));
            Ok(Some(summary))
        }
        Err(error) => {
            run.record("import", "failed", json!(format!("{error:#}")));
            Ok(None)
        }
    }
}

fn fuzz_run_response(
    target: &Path,
    paths: &FuzzPaths,
    run: EngineRun<'_>,
    probe: &bootstrap::WorkspaceProbe,
    selected: &[String],
    summaries: Vec<Value>,
    import_summary: Option<import::FuzzImportSummary>,
) -> Value {
    let imported = import_summary.as_ref().map(|s| s.imported).unwrap_or(0);
    let output = format!(
        "fuzz:run · {} target(s) fuzzed · {} finding(s) imported · {} workorder(s) parked{}",
        selected.len(),
        imported,
        probe.workorders.len(),
        if run.failed { " · BLOCKED (see steps)" } else { "" },
    );
    let data = json!({
        "target": target.display().to_string(),
        "workspaceRoot": paths.workspace_root.display().to_string(),
        "dataRoot": paths.data_root.display().to_string(),
        "steps": run.steps,
        "targets": probe.targets,
        "builtTargets": probe.built.iter().collect::<Vec<_>>(),
        "parkedWorkorders": probe.workorders,
        "roundSummaries": summaries,
        "importSummary": import_summary,
    });
    if run.failed {
        crate::module_result::partial_output_result(
            output.clone(),
            output.clone(),
            vec![json!("one or more engine steps failed; completed progress is durable in the engine workspace")],
            data,
        )
    } else {
        crate::module_result::completed_output_result(output.clone(), output, data)
    }
}

fn fuzz_tool_timeout(input: &Value, label: &str) -> Result<Duration> {
    crate::bounded_subprocess::timeout_from_input(
        input,
        &["timeoutMs", "timeout_ms"],
        DEFAULT_FUZZ_RUN_TIMEOUT_MS,
        MAX_FUZZ_TIMEOUT_MS,
        &format!("{label} timeoutMs"),
    )
}

// ---------------------------------------------------------------------------
// fuzz:author
// ---------------------------------------------------------------------------

pub(in crate::modules) fn run_fuzz_author(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    let runtime = runtime.context("fuzz:author requires a model runtime")?;
    let workspace = ctx
        .workspace
        .context("fuzz:author requires an active workspace")?;
    let paths = match prepare_fuzz_paths(input, &target)? {
        FuzzReadiness::Ready(paths) => paths,
        FuzzReadiness::Skip(reason) => {
            return Ok(fuzz_skipped_response("fuzz:author", &target, &reason))
        }
    };
    let probe = bootstrap::probe_workspace(&paths.workspace_root);
    let filter = optional_string_input(input, &["afeTarget", "afe_target", "shard"])?;
    let workorders: Vec<String> = probe
        .workorders
        .iter()
        .filter(|name| filter.as_deref().is_none_or(|f| f == name.as_str()))
        .cloned()
        .collect();
    if workorders.is_empty() {
        let output = "fuzz:author · no parked workorders to author".to_string();
        return Ok(crate::module_result::completed_output_result(
            output.clone(),
            output,
            json!({ "target": target.display().to_string(), "workorders": [] }),
        ));
    }
    let cfg = author_config(input, ctx, paths)?;
    let spend = crate::spend::SpendLimiter::open_with_hard_ceiling(
        workspace.findings_db_path(),
        ctx.config.operator.spend_hard_ceiling_usd,
    )?;
    let report = author::run_author(runtime, Some(&spend), &cfg, &workorders, ctx.cancellation)?;
    Ok(author_response(&target, report))
}

fn author_config(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    paths: FuzzPaths,
) -> Result<author::AuthorConfig> {
    Ok(author::AuthorConfig {
        paths,
        model: resolve_tool_model("fuzz:author", input, ctx)?,
        budget_usd: f64_input(input, &["budgetUsd", "budget_usd"], 5.0),
        max_targets: u64_input(input, &["maxTargets", "max_targets"], 3) as usize,
        max_steps: u64_input(input, &["maxSteps", "max_steps"], 24) as u32,
        smoke_seconds: u64_input(input, &["smokeSeconds", "smoke_seconds"], 30),
        build_timeout: Duration::from_millis(u64_input(
            input,
            &["buildTimeoutMs", "build_timeout_ms"],
            900_000,
        )),
    })
}

fn f64_input(input: &Value, keys: &[&str], default: f64) -> f64 {
    keys.iter()
        .filter_map(|key| input.get(*key))
        .find_map(Value::as_f64)
        .unwrap_or(default)
}

fn author_response(target: &Path, report: author::AuthorReport) -> Value {
    let authored = report.targets.iter().filter(|t| t.authored).count();
    let output = format!(
        "fuzz:author · {authored}/{} harness(es) authored · ${:.2} spent{}",
        report.targets.len(),
        report.total_cost_usd,
        if report.budget_exhausted { " · budget exhausted" } else { "" },
    );
    let mut result = crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "report": report,
        }),
    );
    result["costUsd"] = json!(report.total_cost_usd);
    result
}

// ---------------------------------------------------------------------------
// fuzz:import + fuzz:status
// ---------------------------------------------------------------------------

pub(in crate::modules) fn run_fuzz_import(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    let workspace = ctx
        .workspace
        .context("fuzz:import requires an active workspace")?;
    let data_root = match optional_string_input(input, &["dataRoot", "data_root"])? {
        Some(value) => PathBuf::from(value),
        None => FuzzPaths::data_root_for(&derived_workspace_root(&home_dir()?, &target)),
    };
    let filter = optional_string_input(input, &["afeTarget", "afe_target", "shard"])?;
    let request = import::FuzzImportRequest {
        data_root: &data_root,
        source_dir: &target,
        target_filter: filter.as_deref(),
        include_unverified: bool_input(input, &["includeUnverified", "include_unverified"]),
    };
    let summary = import::import_afe_findings(workspace, &request)?;
    let output = format!(
        "fuzz:import · {} imported · {} unverified skipped · {} malformed rows",
        summary.imported, summary.skipped_unverified, summary.skipped_rows
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "target": target.display().to_string(), "summary": summary }),
    ))
}

pub(in crate::modules) fn run_fuzz_status(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    let workspace_root = match optional_string_input(input, &["workspaceRoot", "workspace_root"])? {
        Some(value) => PathBuf::from(value),
        None => derived_workspace_root(&home_dir()?, &target),
    };
    let data_root = match optional_string_input(input, &["dataRoot", "data_root"])? {
        Some(value) => PathBuf::from(value),
        None => FuzzPaths::data_root_for(&workspace_root),
    };
    let probe = bootstrap::probe_workspace(&workspace_root);
    let counts = index_counts(&data_root);
    let output = fuzz_status_output(&workspace_root, &probe, counts);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "workspaceRoot": workspace_root.display().to_string(),
            "dataRoot": data_root.display().to_string(),
            "initialized": probe.initialized,
            "sinksPresent": probe.sinks_present,
            "targets": probe.targets,
            "builtTargets": probe.built.iter().collect::<Vec<_>>(),
            "parkedWorkorders": probe.workorders,
            "findings": counts.map(|(verified, total)| json!({
                "verified": verified,
                "total": total,
            })),
        }),
    ))
}

fn index_counts(data_root: &Path) -> Option<(usize, usize)> {
    let body = crate::bounded_file::read_utf8_text(
        &data_root.join("findings-index.jsonl"),
        64 * 1024 * 1024,
    )
    .ok()?;
    let (folded, _) = crate::capabilities::fuzz_engine::index_rows::parse_and_fold(&body);
    let verified = folded.iter().filter(|row| row.recorded.verified).count();
    Some((verified, folded.len()))
}

fn fuzz_status_output(
    workspace_root: &Path,
    probe: &bootstrap::WorkspaceProbe,
    counts: Option<(usize, usize)>,
) -> String {
    if !probe.initialized {
        return format!(
            "fuzz:status · engine workspace {} is uninitialized (fuzz:run bootstraps it)",
            workspace_root.display()
        );
    }
    let findings = counts
        .map(|(verified, total)| format!("{verified}/{total} verified findings"))
        .unwrap_or_else(|| "no findings index".to_string());
    format!(
        "fuzz:status · {} target(s), {} built, {} workorder(s) parked · {}",
        probe.targets.len(),
        probe.built.len(),
        probe.workorders.len(),
        findings,
    )
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, label: impl Into<String>) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, label.into()).emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_descriptors_declare_the_agreed_policies() {
        let module = fuzz_module();
        let tools: std::collections::BTreeMap<&str, &ToolDescriptor> = module
            .tools()
            .iter()
            .map(|tool| (tool.name.as_str(), tool))
            .collect();

        let run = tools["fuzz:run"];
        assert_eq!(run.phase, ToolPhase::Scan);
        assert_eq!(run.runtime_requirement, RuntimeRequirement::Never);
        assert_eq!(run.effect, ToolEffect::RepositoryExecute);
        assert_eq!(run.approval, ApprovalPolicy::Explicit);

        let author = tools["fuzz:author"];
        assert_eq!(author.phase, ToolPhase::Map);
        assert_eq!(author.runtime_requirement, RuntimeRequirement::Always);
        assert_eq!(author.approval, ApprovalPolicy::Explicit);

        let import = tools["fuzz:import"];
        assert_eq!(import.effect, ToolEffect::WorkspaceWrite);
        assert_eq!(import.runtime_requirement, RuntimeRequirement::Never);

        let status = tools["fuzz:status"];
        assert_eq!(status.effect, ToolEffect::Read);
        assert_eq!(status.approval, ApprovalPolicy::None);
    }

    #[test]
    fn missing_afe_repo_is_an_explicit_skip_and_invalid_repo_is_an_error() {
        let temp = tempfile::tempdir().unwrap();
        match prepare_fuzz_paths(&json!({}), temp.path()).unwrap() {
            FuzzReadiness::Skip(reason) => assert!(reason.contains("afeRepo"), "{reason}"),
            FuzzReadiness::Ready(_) => panic!("must skip without afeRepo"),
        }

        let error = prepare_fuzz_paths(
            &json!({"afeRepo": temp.path().join("nope").display().to_string()}),
            temp.path(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not an agentic-fuzz-engine checkout"), "{error}");
    }

    #[test]
    fn engine_workspace_may_not_live_inside_the_scanned_repository() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path();
        let inside = target.join(".kuzushi/fuzz-ws");

        let error = resolve_engine_workspace_root(
            &json!({"workspaceRoot": inside.display().to_string()}),
            target,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("outside the scanned repository"), "{error}");
    }

    #[test]
    fn sequence_generator_specs_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let paths = FuzzPaths {
            afe_repo: temp.path().join("afe"),
            python_bin: temp.path().join("python"),
            workspace_root: temp.path().join("ws"),
            data_root: temp.path().join("ws/data"),
            source_dir: temp.path().join("repo"),
        };
        std::fs::create_dir_all(temp.path().join("ws/generators")).unwrap();
        std::fs::write(
            temp.path().join("ws/generators/seq.json"),
            r#"{"type": "sequence"}"#,
        )
        .unwrap();
        std::fs::write(
            temp.path().join("ws/generators/ok.json"),
            r#"{"type": "direct_call"}"#,
        )
        .unwrap();

        let error = validate_generator_spec(&paths, Some("seq")).unwrap_err().to_string();
        assert!(error.contains("sequence"), "{error}");
        validate_generator_spec(&paths, Some("ok")).unwrap();
        // A spec that is not readable yet is deferred to the engine.
        validate_generator_spec(&paths, Some("not-there-yet")).unwrap();
        validate_generator_spec(&paths, None).unwrap();
    }

    /// A campaign plan row for a non-scope-file tool carries
    /// `{"paths": [...], "shard": "<name>"}` verbatim; both fuzz job tools
    /// must accept that shape, with `shard` canonicalizing to `afeTarget`.
    #[test]
    fn campaign_job_row_input_round_trips_prepare_for_both_fuzz_tools() {
        let registry = crate::modules::ModuleRegistry::with_v2_builtins_without_optional_adapters();
        let row = json!({"paths": ["src/cpp/code/vhdx"], "shard": "vhdx"});

        for tool in ["fuzz:run", "fuzz:author"] {
            let prepared = registry
                .prepare_tool_input(tool, row.clone(), None)
                .unwrap_or_else(|error| panic!("{tool}: {error:#}"));
            assert_eq!(prepared["afeTarget"], json!("vhdx"), "{tool}");
            assert_eq!(prepared["paths"], json!(["src/cpp/code/vhdx"]), "{tool}");
        }
    }

    /// Prompt seasoning writes a TRIAGE_PROMPT option key the fuzz tools do
    /// not declare — a seasoned fuzz campaign must fail prepare LOUDLY
    /// (operators pass seasonPrompts=false), never dispatch silently.
    #[test]
    fn seasoned_campaign_row_fails_prepare_loudly() {
        let registry = crate::modules::ModuleRegistry::with_v2_builtins_without_optional_adapters();

        let error = registry
            .prepare_tool_input(
                "fuzz:run",
                json!({"shard": "vhdx", "TRIAGE_PROMPT": "seasoned"}),
                None,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("TRIAGE_PROMPT"), "{error}");
    }

    #[test]
    fn status_output_reports_uninitialized_and_initialized_workspaces() {
        let empty = bootstrap::WorkspaceProbe::default();
        let output = fuzz_status_output(Path::new("/ws"), &empty, None);
        assert!(output.contains("uninitialized"), "{output}");

        let probe = bootstrap::WorkspaceProbe {
            initialized: true,
            sinks_present: true,
            targets: vec!["a".into(), "b".into()],
            built: ["a".to_string()].into_iter().collect(),
            workorders: vec!["b".into()],
        };
        let output = fuzz_status_output(Path::new("/ws"), &probe, Some((2, 5)));
        assert!(output.contains("2 target(s), 1 built, 1 workorder(s)"), "{output}");
        assert!(output.contains("2/5 verified"), "{output}");
    }
}
