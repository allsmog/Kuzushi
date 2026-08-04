use super::*;
use crate::capabilities::fuzz_engine::{
    author, bootstrap, derived_workspace_root, engine_cli, import, index_rows, prove, provision,
    rounds, FuzzPaths,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DEFAULT_FUZZ_RUN_TIMEOUT_MS: u64 = 60 * 60 * 1000;
const MAX_FUZZ_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;
const WORKSPACE_INIT_TIMEOUT: Duration = Duration::from_secs(300);
const SINK_SCAN_TIMEOUT: Duration = Duration::from_secs(1800);
const GENERATE_TIMEOUT: Duration = Duration::from_secs(1800);
const PROVISION_STEP_TIMEOUT: Duration = Duration::from_secs(300);

pub(in crate::modules) fn fuzz_module() -> BuiltinModule {
    builtin_module(
        "fuzz",
        "Fuzzing (agentic-fuzz-engine)",
        ModuleKind::Scan,
        "Drive the external agentic-fuzz-engine as a scan-phase capability: bootstrap an \
         engine workspace outside the repo, run bounded libFuzzer/SymCC/KLEE rounds, author \
         harnesses for parked workorders through the model runtime, and import verified \
         crashes into the findings store.",
        fuzz_tools(),
        vec![dag("fuzz:run", "fuzz", &[])],
    )
    .labs()
}

fn fuzz_tools() -> Vec<ToolDescriptor> {
    vec![
        fuzz_run_tool(),
        fuzz_author_tool(),
        fuzz_import_tool(),
        fuzz_prove_tool(),
        fuzz_sweep_tool(),
        fuzz_differential_tool(),
        fuzz_status_tool(),
    ]
}

fn fuzz_run_tool() -> ToolDescriptor {
    tool_with_options(
        "fuzz:run",
        "Bootstrap the engine workspace (init, sink scan, deterministic generation, builds) \
         as needed, run bounded fuzz campaign rounds, and import verified crashes. Without \
         afeRepo the pinned engine revision is auto-cloned into the cache; a failed provision \
         returns an explicit skipped result.",
        fuzz_run_options(),
    )
    .with_policy(repository_execute_policy(
        ToolPhase::Scan,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Required,
    ))
}

fn fuzz_author_tool() -> ToolDescriptor {
    tool_with_options(
        "fuzz:author",
        "Author harnesses for the engine's parked workorders through a Rust-driven model tool \
         loop: the model reads sources and workorders, writes harness/build files under hard \
         containment, and iterates the compile/smoke tools; a deterministic verdict grades \
         each target.",
        fuzz_author_options(),
    )
    .with_policy(repository_execute_policy(
        ToolPhase::Map,
        RuntimeRequirement::Always,
        FindingStoreRequirement::Required,
    ))
}

fn fuzz_import_tool() -> ToolDescriptor {
    tool_with_options(
        "fuzz:import",
        "Import the engine's verified crash ledger (findings-index.jsonl) into the findings \
         store with impact-derived severity, without running the engine.",
        fuzz_import_options(),
    )
    .with_policy(workspace_policy(
        ToolPhase::Scan,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Required,
    ))
}

fn fuzz_prove_tool() -> ToolDescriptor {
    tool_with_options(
        "fuzz:prove",
        "Run the engine's per-finding impact pass (PoV replay for the ASAN primitive, UBSan \
         wrap evidence, flag-profile matrix, adjacency leads) over verified findings that \
         lack an impact verdict, then refresh the import so impact-derived severity lands in \
         the findings store.",
        fuzz_prove_options(),
    )
    .with_policy(repository_execute_policy(
        ToolPhase::Prove,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Required,
    ))
}

fn fuzz_sweep_tool() -> ToolDescriptor {
    tool_with_options(
        "fuzz:sweep",
        "Build a sanitizer-variant fuzzer (MSan uninitialized-read or TSan race oracle) for \
         one engine target and replay its corpus in keep-going mode with benign-input \
         baseline subtraction, reporting input-dependent signature groups ranked \
         write-first.",
        fuzz_sweep_options(),
    )
    .with_policy(repository_execute_policy(
        ToolPhase::Scan,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Optional,
    ))
}

fn fuzz_differential_tool() -> ToolDescriptor {
    tool_with_options(
        "fuzz:differential",
        "Replay one engine target's corpus through N implementations (fork vs upstream, or \
         one command as a metamorphic self-check) and rank the divergences: crash-split first, \
         then validity- and output-splits — the silent-wrong-data oracle the crash lane never \
         fires on.",
        fuzz_differential_options(),
    )
    .with_policy(repository_execute_policy(
        ToolPhase::Scan,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Optional,
    ))
}

fn fuzz_status_tool() -> ToolDescriptor {
    tool_with_options(
        "fuzz:status",
        "Probe the engine workspace: bootstrap state, targets, built fuzzers, parked \
         workorders, and verified finding counts. Read-only, no engine invocation.",
        fuzz_status_options(),
    )
    .with_policy(read_policy(ToolPhase::Scan, WorkspaceRequirement::Required))
}

fn shared_engine_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        opt(
            "afeRepo",
            OptionType::Path,
            "agentic-fuzz-engine checkout (must contain src/agentic_fuzz_engine/cli.py). \
             When omitted, the pinned engine revision is auto-cloned into \
             ~/.cache/agentic-fuzz/engine-<rev8> and reused across runs.",
        )
        .external_read()
        .aliases(&["afe_repo"]),
        opt(
            "afeGitUrl",
            OptionType::String,
            "Engine git remote used for auto-provisioning when afeRepo is omitted.",
        )
        .aliases(&["afe_git_url"])
        .default(json!(provision::DEFAULT_AFE_GIT_URL))
        .advanced(),
        opt(
            "afeRev",
            OptionType::String,
            "Pinned engine commit (full 40-hex sha) for auto-provisioning. Bump deliberately; \
             each rev gets its own cache directory.",
        )
        .aliases(&["afe_rev"])
        .default(json!(provision::DEFAULT_AFE_REV))
        .advanced(),
        opt(
            "afeGitSshKey",
            OptionType::Path,
            "ssh private key for the engine remote when the ambient ssh config cannot reach \
             it (built into GIT_SSH_COMMAND with IdentitiesOnly/BatchMode).",
        )
        .external_read()
        .aliases(&["afe_git_ssh_key"])
        .advanced(),
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
            "kleeConfig",
            OptionType::String,
            "KLEE ci-pack JSON enabling the periodic KLEE lane: a name/path relative to \
             <workspaceRoot>/klee/ or an absolute path. Requires the klee-ng docker image; \
             the engine validates both and reports blockers.",
        )
        .aliases(&["klee_config"]),
        opt(
            "kleeEvery",
            OptionType::Int,
            "KLEE fires on every kleeEvery-th round (unset = engine policy default 4).",
        )
        .aliases(&["klee_every"])
        .integer_range(1, 24)
        .advanced(),
        opt(
            "kleeSeconds",
            OptionType::Int,
            "KLEE lane wall-clock per firing round (engine hard-caps at 3600).",
        )
        .aliases(&["klee_seconds"])
        .integer_range(60, 3_600)
        .default(json!(900))
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

fn fuzz_prove_options() -> Vec<OptionSpec> {
    let mut options = shared_engine_options();
    options.extend(vec![
        opt(
            "findingId",
            OptionType::String,
            "Impact-grade exactly this engine finding id (re-grades even one that already \
             has an impact verdict — the pass is a deterministic replay).",
        )
        .aliases(&["finding_id"]),
        opt(
            "runId",
            OptionType::String,
            "Only grade findings recorded under this engine run id.",
        )
        .aliases(&["run_id"]),
        opt(
            "maxFindings",
            OptionType::Int,
            "Cap on findings graded this invocation.",
        )
        .aliases(&["max_findings"])
        .integer_range(1, 25)
        .default(json!(5)),
        opt(
            "replayTimeoutSeconds",
            OptionType::Int,
            "Per-replay-lane deadline inside the engine's impact pass.",
        )
        .aliases(&["replay_timeout_seconds"])
        .integer_range(5, 600)
        .default(json!(60))
        .advanced(),
        opt(
            "skipImport",
            OptionType::Bool,
            "Grade impact without refreshing the findings-store import afterwards.",
        )
        .aliases(&["skip_import"])
        .default(json!(false))
        .advanced(),
        fuzz_timeout_option(),
    ]);
    options
}

fn fuzz_sweep_options() -> Vec<OptionSpec> {
    let mut options = shared_engine_options();
    options.extend(vec![
        opt(
            "sanitizer",
            OptionType::String,
            "Sanitizer variant to build and sweep with. MSan finds uninitialized reads the \
             ASAN lane cannot; TSan needs a target that actually spawns threads. Without \
             afeTarget, every built target is swept in turn (budget = maxSeconds each).",
        )
        .choices(&["msan", "tsan"])
        .default(json!("msan")),
        opt(
            "rebuild",
            OptionType::Bool,
            "Rebuild the variant fuzzer even when bin/<target>/fuzzer-<sanitizer> exists.",
        )
        .default(json!(false))
        .advanced(),
        opt(
            "maxInputs",
            OptionType::Int,
            "Cap on corpus inputs replayed this sweep.",
        )
        .aliases(&["max_inputs"])
        .integer_range(1, 100_000)
        .default(json!(2000)),
        opt(
            "runsPerInput",
            OptionType::Int,
            "Repetitions per input (TSan interleavings need more than one).",
        )
        .aliases(&["runs_per_input"])
        .integer_range(1, 16)
        .default(json!(1))
        .advanced(),
        opt(
            "perInputTimeoutSeconds",
            OptionType::Int,
            "Per-input replay deadline inside the sweep.",
        )
        .aliases(&["per_input_timeout_seconds"])
        .integer_range(1, 300)
        .default(json!(15))
        .advanced(),
        opt(
            "maxSeconds",
            OptionType::Int,
            "Whole-sweep replay budget (the engine reports budget_exhausted past it).",
        )
        .aliases(&["max_seconds"])
        .integer_range(30, 21_600)
        .default(json!(900)),
        opt(
            "buildTimeoutSeconds",
            OptionType::Int,
            "Variant-build deadline when the sweep has to build the fuzzer first.",
        )
        .aliases(&["build_timeout_seconds"])
        .integer_range(60, 7200)
        .default(json!(1200))
        .advanced(),
        opt("top", OptionType::Int, "Signature groups kept in the report.")
            .integer_range(1, 500)
            .default(json!(50))
            .advanced(),
        fuzz_timeout_option(),
    ]);
    options
}

fn fuzz_differential_options() -> Vec<OptionSpec> {
    let mut options = shared_engine_options();
    options.extend(vec![
        opt(
            "commands",
            OptionType::StringList,
            "One replay argv per implementation, each as a single string with an optional \
             {input} placeholder (appended otherwise). A single command is treated as a \
             metamorphic self-check. Omit for auto mode: the engine resolves (and builds) \
             implementations from the target's .localfuzz/differential.json recipe or its \
             bin/<t>/replay* binaries, and honestly skips targets with fewer than two.",
        )
        .aliases(&["command"]),
        opt(
            "labels",
            OptionType::StringList,
            "Implementation labels, positionally matching commands.",
        )
        .aliases(&["label"])
        .advanced(),
        opt(
            "compare",
            OptionType::String,
            "behavior compares exit classes only; output also diffs stdout hashes.",
        )
        .choices(&["behavior", "output"])
        .default(json!("behavior")),
        opt(
            "corpusDir",
            OptionType::Path,
            "Corpus directory to replay. Defaults to the engine target's corpus.",
        )
        .external_read()
        .aliases(&["corpus_dir"])
        .advanced(),
        opt(
            "maxInputs",
            OptionType::Int,
            "Cap on corpus inputs replayed this run.",
        )
        .aliases(&["max_inputs"])
        .integer_range(1, 100_000)
        .default(json!(2000)),
        opt(
            "perInputTimeoutSeconds",
            OptionType::Int,
            "Per-input, per-implementation replay deadline.",
        )
        .aliases(&["per_input_timeout_seconds"])
        .integer_range(1, 300)
        .default(json!(10))
        .advanced(),
        opt(
            "maxSeconds",
            OptionType::Int,
            "Whole-run replay budget (the engine reports budget_exhausted past it).",
        )
        .aliases(&["max_seconds"])
        .integer_range(30, 21_600)
        .default(json!(900)),
        opt("top", OptionType::Int, "Divergences kept in the report.")
            .integer_range(1, 500)
            .default(json!(50))
            .advanced(),
        fuzz_timeout_option(),
    ]);
    options
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
    let afe_repo = match resolve_afe_repo(input)? {
        RepoResolution::Ready(path) => path,
        RepoResolution::Skip(reason) => return Ok(FuzzReadiness::Skip(reason)),
    };
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

#[derive(Debug)]
enum RepoResolution {
    Ready(PathBuf),
    Skip(String),
}

/// An explicit `afeRepo` must be a valid checkout (hard error otherwise);
/// without one, the pinned engine revision is auto-provisioned into the
/// cache. A failed provision skips the tool with actionable guidance rather
/// than failing a whole campaign wave on a box that cannot reach the remote.
fn resolve_afe_repo(input: &Value) -> Result<RepoResolution> {
    if let Some(explicit) = optional_string_input(input, &["afeRepo", "afe_repo"])? {
        let path = PathBuf::from(explicit);
        anyhow::ensure!(
            engine_cli::afe_repo_is_valid(&path),
            "afeRepo {} is not an agentic-fuzz-engine checkout (missing src/agentic_fuzz_engine/cli.py)",
            path.display()
        );
        return Ok(RepoResolution::Ready(path));
    }
    let spec = provision_spec_from_input(input)?;
    match provision::provision_engine(&spec) {
        Ok(dir) => Ok(RepoResolution::Ready(dir)),
        Err(error) => Ok(RepoResolution::Skip(format!(
            "auto-provisioning engine rev {} from {} failed ({error:#}) — pass afeRepo \
             (a local checkout) or afeGitSshKey (a key that can read the remote)",
            &spec.rev[..8.min(spec.rev.len())],
            spec.git_url,
        ))),
    }
}

fn provision_spec_from_input(input: &Value) -> Result<provision::ProvisionSpec> {
    Ok(provision::ProvisionSpec {
        git_url: optional_string_input(input, &["afeGitUrl", "afe_git_url"])?
            .unwrap_or_else(|| provision::DEFAULT_AFE_GIT_URL.to_string()),
        rev: optional_string_input(input, &["afeRev", "afe_rev"])?
            .unwrap_or_else(|| provision::DEFAULT_AFE_REV.to_string()),
        ssh_key: optional_string_input(input, &["afeGitSshKey", "afe_git_ssh_key"])?
            .map(PathBuf::from),
        cache_home: home_dir()?.join(".cache/agentic-fuzz"),
        step_timeout: PROVISION_STEP_TIMEOUT,
    })
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
    klee_config: Option<String>,
    klee_every: Option<u64>,
    klee_seconds: u64,
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
            klee_config: optional_string_input(input, &["kleeConfig", "klee_config"])?,
            klee_every: optional_u64_input(input, &["kleeEvery", "klee_every"]),
            klee_seconds: u64_input(input, &["kleeSeconds", "klee_seconds"], 900),
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

    /// The KLEE lane plan for budgeting — present only when a config is set.
    fn klee_lane(&self) -> Option<rounds::KleeLanePlan> {
        self.klee_config.as_ref().map(|_| rounds::KleeLanePlan {
            every: self.klee_every.unwrap_or(rounds::DEFAULT_KLEE_EVERY),
            seconds: self.klee_seconds,
        })
    }
}

fn u64_input(input: &Value, keys: &[&str], default: u64) -> u64 {
    keys.iter()
        .filter_map(|key| input.get(*key))
        .find_map(Value::as_u64)
        .unwrap_or(default)
}

fn optional_u64_input(input: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .filter_map(|key| input.get(*key))
        .find_map(Value::as_u64)
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
    /// Any step failed → the run reports `partial`.
    failed: bool,
    /// A foundation step (init/scan/generate) failed or the deadline hit →
    /// stop scheduling further engine work. One target's build failure is
    /// NOT aborting: the other targets still deserve their rounds.
    aborted: bool,
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
            self.aborted = true;
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
        aborted: false,
    };
    execute_bootstrap(&mut run, &options);
    let probe = bootstrap::probe_workspace(&paths.workspace_root);
    let selected = selected_targets(&probe, options.afe_target.as_deref());
    let summaries = execute_rounds(&mut run, &options, &selected, timeout)?;
    let import_summary = execute_import(&mut run, input, options.skip_import)?;
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
        if run.aborted {
            return;
        }
        let foundation = !matches!(step, bootstrap::BootstrapStep::Build(_));
        let failed_before = run.failed;
        execute_bootstrap_step(run, options, &step);
        // Init/scan/generate failures poison everything downstream; a single
        // target's build failure only costs that target its rounds.
        if foundation && run.failed && !failed_before {
            run.aborted = true;
        }
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
    rounds::round_budget(
        options.rounds,
        options.fuzz_seconds,
        options.klee_lane(),
        selected.len() as u64,
        timeout,
    )?;
    let mut summaries = Vec::new();
    for target in selected {
        if run.aborted {
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
    let args = campaign_round_args(run.paths, options, target);
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

fn campaign_round_args(
    paths: &FuzzPaths,
    options: &FuzzRunOptions,
    target: &str,
) -> Vec<String> {
    let mut args = vec![
        "campaign-round-run".to_string(),
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
        paths.workspace_root.display().to_string(),
    ];
    if let (Some(config), Some(lane)) = (&options.klee_config, options.klee_lane()) {
        // Cadence is passed explicitly so the engine agrees with what
        // round_budget assumed; the engine still owns config/image validation.
        args.extend([
            "--klee-config".into(),
            resolve_klee_config(&paths.workspace_root, config),
            "--klee-every".into(),
            lane.every.to_string(),
            "--klee-seconds".into(),
            lane.seconds.to_string(),
        ]);
    }
    args
}

fn resolve_klee_config(workspace_root: &std::path::Path, spec: &str) -> String {
    let path = std::path::Path::new(spec);
    if path.is_absolute() {
        return spec.to_string();
    }
    workspace_root.join("klee").join(spec).display().to_string()
}

fn execute_import(
    run: &mut EngineRun<'_>,
    input: &Value,
    skip_import: bool,
) -> Result<Option<import::FuzzImportSummary>> {
    if skip_import {
        run.record_skip("import", "skipImport requested");
        return Ok(None);
    }
    // A workspace that never recorded a finding has no index yet — that is
    // a clean zero-import, not a failure.
    if !run.paths.data_root.join("findings-index.jsonl").is_file() {
        run.record_skip("import", "no findings index yet (engine recorded nothing)");
        return Ok(None);
    }
    let Some(workspace) = run.ctx.workspace else {
        run.record("import", "failed", json!("no active workspace for the findings store"));
        run.failed = true;
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
            run.failed = true;
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
        "fuzz:run · {}/{} selected target(s) fuzzed · {} finding(s) imported · {} workorder(s) parked{}",
        summaries.len(),
        selected.len(),
        imported,
        probe.workorders.len(),
        if run.failed { " · PARTIAL (see steps)" } else { "" },
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
// fuzz:prove
// ---------------------------------------------------------------------------

/// The impact pass replays one PoV several times (flag-profile matrix plus
/// oracle lanes), so its step budget is a multiple of the per-replay deadline.
const PROVE_LANES_PER_FINDING: u64 = 10;
const PROVE_STEP_SLACK: Duration = Duration::from_secs(120);

struct FuzzProveOptions {
    filter: prove::ProveFilter,
    max_findings: usize,
    replay_timeout_seconds: u64,
    skip_import: bool,
}

impl FuzzProveOptions {
    fn parse(input: &Value) -> Result<Self> {
        Ok(Self {
            filter: prove::ProveFilter {
                target: optional_string_input(input, &["afeTarget", "afe_target", "shard"])?,
                run_id: optional_string_input(input, &["runId", "run_id"])?,
                finding_id: optional_string_input(input, &["findingId", "finding_id"])?,
            },
            max_findings: u64_input(input, &["maxFindings", "max_findings"], 5) as usize,
            replay_timeout_seconds: u64_input(
                input,
                &["replayTimeoutSeconds", "replay_timeout_seconds"],
                60,
            ),
            skip_import: bool_input(input, &["skipImport", "skip_import"]),
        })
    }

    fn step_timeout(&self) -> Duration {
        Duration::from_secs(self.replay_timeout_seconds * PROVE_LANES_PER_FINDING)
            + PROVE_STEP_SLACK
    }
}

pub(in crate::modules) fn run_fuzz_prove(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    let paths = match prepare_fuzz_paths(input, &target)? {
        FuzzReadiness::Ready(paths) => paths,
        FuzzReadiness::Skip(reason) => {
            return Ok(fuzz_skipped_response("fuzz:prove", &target, &reason))
        }
    };
    let options = FuzzProveOptions::parse(input)?;
    let candidates = prove_candidates(&paths, &options)?;
    let timeout = fuzz_tool_timeout(input, "fuzz:prove")?;
    let mut run = EngineRun {
        ctx,
        paths: &paths,
        deadline: Instant::now() + timeout,
        steps: Vec::new(),
        failed: false,
        aborted: false,
    };
    let verdicts = execute_impact_passes(&mut run, &options, &candidates);
    let import_summary = if verdicts.is_empty() {
        run.record_skip("import", "no impact verdicts to fold");
        None
    } else {
        execute_import(&mut run, input, options.skip_import)?
    };
    Ok(fuzz_prove_response(&target, &paths, run, &candidates, verdicts, import_summary))
}

/// Fold the durable findings index and pick the rows worth an impact pass.
/// A missing index means the engine never recorded anything — a clean zero.
fn prove_candidates(
    paths: &FuzzPaths,
    options: &FuzzProveOptions,
) -> Result<Vec<prove::ProveCandidate>> {
    let index_path = paths.data_root.join("findings-index.jsonl");
    let Ok(body) = crate::bounded_file::read_utf8_text(&index_path, 64 * 1024 * 1024) else {
        return Ok(Vec::new());
    };
    let (folded, _) = index_rows::parse_and_fold(&body);
    Ok(prove::select_candidates(&folded, &options.filter, options.max_findings))
}

fn execute_impact_passes(
    run: &mut EngineRun<'_>,
    options: &FuzzProveOptions,
    candidates: &[prove::ProveCandidate],
) -> Vec<Value> {
    if candidates.is_empty() {
        run.record_skip("finding-impact", "no verified findings awaiting an impact verdict");
        return Vec::new();
    }
    let ws = run.paths.workspace_root.display().to_string();
    let mut verdicts = Vec::new();
    for candidate in candidates {
        if run.aborted {
            break;
        }
        let args = vec![
            "finding-impact".into(),
            candidate.run_id.clone(),
            candidate.finding_id.clone(),
            "--workspace-root".into(),
            ws.clone(),
            "--timeout-seconds".into(),
            options.replay_timeout_seconds.to_string(),
        ];
        let label = format!("finding-impact {}", candidate.finding_id);
        if let Some(payload) = run.engine_step(&label, args, options.step_timeout()) {
            verdicts.push(prove::verdict_from_payload(candidate, &payload));
        }
    }
    verdicts
}

fn fuzz_prove_response(
    target: &Path,
    paths: &FuzzPaths,
    run: EngineRun<'_>,
    candidates: &[prove::ProveCandidate],
    verdicts: Vec<Value>,
    import_summary: Option<import::FuzzImportSummary>,
) -> Value {
    let write_class = verdicts.iter().filter(|v| prove::verdict_is_write_class(v)).count();
    let output = format!(
        "fuzz:prove · {}/{} finding(s) impact-graded · {} write-class · {} import refresh{}",
        verdicts.len(),
        candidates.len(),
        write_class,
        import_summary
            .as_ref()
            .map(|s| s.imported.to_string())
            .unwrap_or_else(|| "no".to_string()),
        if run.failed { " · PARTIAL (see steps)" } else { "" },
    );
    let data = json!({
        "target": target.display().to_string(),
        "workspaceRoot": paths.workspace_root.display().to_string(),
        "dataRoot": paths.data_root.display().to_string(),
        "steps": run.steps,
        "candidates": candidates.len(),
        "verdicts": verdicts,
        "writeClass": write_class,
        "importSummary": import_summary,
    });
    if run.failed {
        crate::module_result::partial_output_result(
            output.clone(),
            output.clone(),
            vec![json!("one or more impact passes failed; completed verdicts are durable in the findings index")],
            data,
        )
    } else {
        crate::module_result::completed_output_result(output.clone(), output, data)
    }
}

// ---------------------------------------------------------------------------
// fuzz:sweep
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FuzzSweepOptions {
    /// Absent → sweep every built target in the workspace.
    afe_target: Option<String>,
    sanitizer: String,
    rebuild: bool,
    max_inputs: u64,
    runs_per_input: u64,
    per_input_timeout_seconds: u64,
    max_seconds: u64,
    build_timeout_seconds: u64,
    top: u64,
}

impl FuzzSweepOptions {
    fn parse(input: &Value) -> Result<Self> {
        Ok(Self {
            afe_target: optional_string_input(input, &["afeTarget", "afe_target", "shard"])?,
            sanitizer: optional_string_input(input, &["sanitizer"])?
                .unwrap_or_else(|| "msan".to_string()),
            rebuild: bool_input(input, &["rebuild"]),
            max_inputs: u64_input(input, &["maxInputs", "max_inputs"], 2000),
            runs_per_input: u64_input(input, &["runsPerInput", "runs_per_input"], 1),
            per_input_timeout_seconds: u64_input(
                input,
                &["perInputTimeoutSeconds", "per_input_timeout_seconds"],
                15,
            ),
            max_seconds: u64_input(input, &["maxSeconds", "max_seconds"], 900),
            build_timeout_seconds: u64_input(
                input,
                &["buildTimeoutSeconds", "build_timeout_seconds"],
                1200,
            ),
            top: u64_input(input, &["top"], 50),
        })
    }
}

pub(in crate::modules) fn run_fuzz_sweep(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    let paths = match prepare_fuzz_paths(input, &target)? {
        FuzzReadiness::Ready(paths) => paths,
        FuzzReadiness::Skip(reason) => {
            return Ok(fuzz_skipped_response("fuzz:sweep", &target, &reason))
        }
    };
    let options = FuzzSweepOptions::parse(input)?;
    let selected = engine_targets(&paths, options.afe_target.as_deref());
    if selected.is_empty() {
        return Ok(fuzz_skipped_response(
            "fuzz:sweep",
            &target,
            "no built engine targets to sweep — run fuzz:run first to scaffold and build fuzzers",
        ));
    }
    let timeout = fuzz_tool_timeout(input, "fuzz:sweep")?;
    let mut run = EngineRun {
        ctx,
        paths: &paths,
        deadline: Instant::now() + timeout,
        steps: Vec::new(),
        failed: false,
        aborted: false,
    };
    let mut reports = Vec::new();
    for afe_target in &selected {
        if run.aborted {
            break;
        }
        if !ensure_variant_built(&mut run, &options, afe_target) {
            continue;
        }
        if let Some(payload) = execute_sweep(&mut run, &options, afe_target) {
            reports.push(json!({ "afeTarget": afe_target, "sweep": payload }));
        }
    }
    Ok(fuzz_sweep_response(&target, &paths, run, &options, &selected, reports))
}

/// An explicit afeTarget is honored as-is (the engine reports honestly when it
/// does not exist); absent, every built target in the workspace is in scope.
fn engine_targets(paths: &FuzzPaths, filter: Option<&str>) -> Vec<String> {
    match filter {
        Some(name) => vec![name.to_string()],
        None => bootstrap::probe_workspace(&paths.workspace_root)
            .built
            .into_iter()
            .collect(),
    }
}

fn variant_binary(paths: &FuzzPaths, options: &FuzzSweepOptions, afe_target: &str) -> PathBuf {
    paths
        .workspace_root
        .join("bin")
        .join(afe_target)
        .join(format!("fuzzer-{}", options.sanitizer))
}

/// A sweep without its variant binary is meaningless, so a failed build costs
/// that target its sweep (returns false) — the remaining targets still run.
fn ensure_variant_built(
    run: &mut EngineRun<'_>,
    options: &FuzzSweepOptions,
    afe_target: &str,
) -> bool {
    let label = format!("sanitizer-build {afe_target}");
    if !options.rebuild && variant_binary(run.paths, options, afe_target).is_file() {
        run.record_skip(&label, "variant fuzzer already built");
        return true;
    }
    let args = vec![
        "sanitizer-build".into(),
        "--target".into(),
        afe_target.to_string(),
        "--sanitizer".into(),
        options.sanitizer.clone(),
        "--timeout-seconds".into(),
        options.build_timeout_seconds.to_string(),
        "--workspace-root".into(),
        run.paths.workspace_root.display().to_string(),
    ];
    let step_timeout = Duration::from_secs(options.build_timeout_seconds + 60);
    run.engine_step(&label, args, step_timeout).is_some()
}

fn execute_sweep(
    run: &mut EngineRun<'_>,
    options: &FuzzSweepOptions,
    afe_target: &str,
) -> Option<Value> {
    let args = vec![
        "sanitizer-sweep".into(),
        "--target".into(),
        afe_target.to_string(),
        "--sanitizer".into(),
        options.sanitizer.clone(),
        "--max-inputs".into(),
        options.max_inputs.to_string(),
        "--per-input-timeout".into(),
        options.per_input_timeout_seconds.to_string(),
        "--max-seconds".into(),
        options.max_seconds.to_string(),
        "--runs-per-input".into(),
        options.runs_per_input.to_string(),
        "--top".into(),
        options.top.to_string(),
        "--workspace-root".into(),
        run.paths.workspace_root.display().to_string(),
    ];
    run.engine_step(&format!("sanitizer-sweep {afe_target}"), args, run.remaining())
}

fn payload_u64(payload: Option<&Value>, key: &str) -> u64 {
    payload
        .and_then(|value| value.get(key))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn fuzz_sweep_response(
    target: &Path,
    paths: &FuzzPaths,
    run: EngineRun<'_>,
    options: &FuzzSweepOptions,
    selected: &[String],
    reports: Vec<Value>,
) -> Value {
    let inputs: u64 = reports
        .iter()
        .map(|report| payload_u64(report.get("sweep"), "inputs_scanned"))
        .sum();
    let groups: u64 = reports
        .iter()
        .map(|report| payload_u64(report.get("sweep"), "unique_signatures"))
        .sum();
    let output = format!(
        "fuzz:sweep · {} · {}/{} target(s) swept · {} input(s) replayed · \
         {} input-dependent group(s){}",
        options.sanitizer,
        reports.len(),
        selected.len(),
        inputs,
        groups,
        if run.failed { " · PARTIAL (see steps)" } else { "" },
    );
    let data = json!({
        "target": target.display().to_string(),
        "workspaceRoot": paths.workspace_root.display().to_string(),
        "afeTargets": selected,
        "sanitizer": options.sanitizer,
        "steps": run.steps,
        "reports": reports,
    });
    if run.failed {
        crate::module_result::partial_output_result(
            output.clone(),
            output.clone(),
            vec![json!("one or more engine steps failed; see steps")],
            data,
        )
    } else {
        crate::module_result::completed_output_result(output.clone(), output, data)
    }
}

// ---------------------------------------------------------------------------
// fuzz:differential
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FuzzDifferentialOptions {
    /// Absent → replay every built target in auto mode.
    afe_target: Option<String>,
    /// Empty → the engine auto-resolves implementations from the target's
    /// `.localfuzz/differential.json` recipe or its `bin/<t>/replay*` binaries.
    commands: Vec<String>,
    labels: Vec<String>,
    compare: String,
    corpus_dir: Option<String>,
    max_inputs: u64,
    per_input_timeout_seconds: u64,
    max_seconds: u64,
    top: u64,
}

impl FuzzDifferentialOptions {
    fn parse(input: &Value) -> Result<Self> {
        let afe_target = optional_string_input(input, &["afeTarget", "afe_target", "shard"])?;
        let commands = string_list_input(input, &["commands", "command"])?
            .unwrap_or_default();
        anyhow::ensure!(
            commands.is_empty() || afe_target.is_some(),
            "fuzz:differential with explicit commands needs afeTarget \
             (replay argvs are per-target; omit commands for auto mode)"
        );
        let labels = string_list_input(input, &["labels", "label"])?.unwrap_or_default();
        anyhow::ensure!(
            labels.is_empty() || labels.len() == commands.len(),
            "labels ({}) must positionally match commands ({})",
            labels.len(),
            commands.len()
        );
        Ok(Self {
            afe_target,
            commands,
            labels,
            compare: optional_string_input(input, &["compare"])?
                .unwrap_or_else(|| "behavior".to_string()),
            corpus_dir: optional_string_input(input, &["corpusDir", "corpus_dir"])?,
            max_inputs: u64_input(input, &["maxInputs", "max_inputs"], 2000),
            per_input_timeout_seconds: u64_input(
                input,
                &["perInputTimeoutSeconds", "per_input_timeout_seconds"],
                10,
            ),
            max_seconds: u64_input(input, &["maxSeconds", "max_seconds"], 900),
            top: u64_input(input, &["top"], 50),
        })
    }
}

pub(in crate::modules) fn run_fuzz_differential(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    let paths = match prepare_fuzz_paths(input, &target)? {
        FuzzReadiness::Ready(paths) => paths,
        FuzzReadiness::Skip(reason) => {
            return Ok(fuzz_skipped_response("fuzz:differential", &target, &reason))
        }
    };
    let options = FuzzDifferentialOptions::parse(input)?;
    let selected = engine_targets(&paths, options.afe_target.as_deref());
    if selected.is_empty() {
        return Ok(fuzz_skipped_response(
            "fuzz:differential",
            &target,
            "no built engine targets to replay — run fuzz:run first to scaffold and build fuzzers",
        ));
    }
    let timeout = fuzz_tool_timeout(input, "fuzz:differential")?;
    let mut run = EngineRun {
        ctx,
        paths: &paths,
        deadline: Instant::now() + timeout,
        steps: Vec::new(),
        failed: false,
        aborted: false,
    };
    let mut reports = Vec::new();
    for afe_target in &selected {
        if run.aborted {
            break;
        }
        let label = format!("differential-run {afe_target}");
        let args = differential_args(&paths, &options, afe_target);
        if let Some(payload) = run.engine_step(&label, args, run.remaining()) {
            reports.push(json!({ "afeTarget": afe_target, "differential": payload }));
        }
    }
    Ok(fuzz_differential_response(&target, &paths, run, &options, &selected, reports))
}

fn differential_args(
    paths: &FuzzPaths,
    options: &FuzzDifferentialOptions,
    afe_target: &str,
) -> Vec<String> {
    let mut args = vec![
        "differential-run".to_string(),
        "--target".into(),
        afe_target.to_string(),
    ];
    if options.commands.is_empty() {
        args.push("--auto".into());
    }
    for command in &options.commands {
        args.push("--command".into());
        args.push(command.clone());
    }
    for label in &options.labels {
        args.push("--label".into());
        args.push(label.clone());
    }
    if let Some(corpus) = &options.corpus_dir {
        args.push("--corpus-dir".into());
        args.push(corpus.clone());
    }
    args.extend([
        "--compare".into(),
        options.compare.clone(),
        "--max-inputs".into(),
        options.max_inputs.to_string(),
        "--per-input-timeout".into(),
        options.per_input_timeout_seconds.to_string(),
        "--max-seconds".into(),
        options.max_seconds.to_string(),
        "--top".into(),
        options.top.to_string(),
        "--workspace-root".into(),
        paths.workspace_root.display().to_string(),
    ]);
    args
}

fn fuzz_differential_response(
    target: &Path,
    paths: &FuzzPaths,
    run: EngineRun<'_>,
    options: &FuzzDifferentialOptions,
    selected: &[String],
    reports: Vec<Value>,
) -> Value {
    let mut divergent = 0u64;
    let mut crash_splits = 0u64;
    let mut skip_notes = Vec::new();
    for report in &reports {
        let payload = report.get("differential");
        let skipped = payload
            .and_then(|value| value.get("skipped"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if skipped {
            let afe_target = report["afeTarget"].as_str().unwrap_or("?");
            let reason = payload
                .and_then(|value| value.get("skip_reason"))
                .and_then(Value::as_str)
                .unwrap_or("skipped");
            skip_notes.push(format!("{afe_target}: {reason}"));
            continue;
        }
        divergent += payload_u64(payload, "divergent");
        crash_splits += payload
            .and_then(|value| value.get("counts_by_kind"))
            .and_then(|counts| counts.get("crash-split"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
    }
    let mode = if options.commands.is_empty() { "auto" } else { "explicit" };
    let output = format!(
        "fuzz:differential · {mode} · {}/{} target(s) replayed · {} divergence(s), \
         {} crash-split(s){}{}",
        reports.len(),
        selected.len(),
        divergent,
        crash_splits,
        if skip_notes.is_empty() {
            String::new()
        } else {
            format!(" · {} skipped", skip_notes.len())
        },
        if run.failed { " · PARTIAL (see steps)" } else { "" },
    );
    let data = json!({
        "target": target.display().to_string(),
        "workspaceRoot": paths.workspace_root.display().to_string(),
        "afeTargets": selected,
        "mode": mode,
        "skipNotes": skip_notes,
        "steps": run.steps,
        "reports": reports,
    });
    if run.failed {
        crate::module_result::partial_output_result(
            output.clone(),
            output.clone(),
            vec![json!("the differential replay failed; see steps")],
            data,
        )
    } else {
        crate::module_result::completed_output_result(output.clone(), output, data)
    }
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

        let prove = tools["fuzz:prove"];
        assert_eq!(prove.phase, ToolPhase::Prove);
        assert_eq!(prove.runtime_requirement, RuntimeRequirement::Never);
        assert_eq!(prove.effect, ToolEffect::RepositoryExecute);
        assert_eq!(prove.approval, ApprovalPolicy::Explicit);

        let sweep = tools["fuzz:sweep"];
        assert_eq!(sweep.phase, ToolPhase::Scan);
        assert_eq!(sweep.runtime_requirement, RuntimeRequirement::Never);
        assert_eq!(sweep.effect, ToolEffect::RepositoryExecute);
        assert_eq!(sweep.approval, ApprovalPolicy::Explicit);

        let differential = tools["fuzz:differential"];
        assert_eq!(differential.phase, ToolPhase::Scan);
        assert_eq!(differential.runtime_requirement, RuntimeRequirement::Never);
        assert_eq!(differential.effect, ToolEffect::RepositoryExecute);
        assert_eq!(differential.approval, ApprovalPolicy::Explicit);

        let status = tools["fuzz:status"];
        assert_eq!(status.effect, ToolEffect::Read);
        assert_eq!(status.approval, ApprovalPolicy::None);
    }

    #[test]
    fn sweep_options_default_to_all_built_targets_and_fold_defaults() {
        // A planner-dispatched `{}` must parse: no target means "every built
        // target", resolved at execution time.
        let options = FuzzSweepOptions::parse(&json!({})).unwrap();
        assert_eq!(options.afe_target, None);
        assert_eq!(options.sanitizer, "msan");
        assert_eq!(options.max_inputs, 2000);
        assert!(!options.rebuild);

        let tsan = FuzzSweepOptions::parse(&json!({
            "shard": "tsk_bdi", "sanitizer": "tsan", "runsPerInput": 4, "rebuild": true,
        }))
        .unwrap();
        assert_eq!(tsan.afe_target.as_deref(), Some("tsk_bdi"));
        assert_eq!(tsan.sanitizer, "tsan");
        assert_eq!(tsan.runs_per_input, 4);
        assert!(tsan.rebuild);
    }

    #[test]
    fn engine_target_selection_honors_explicit_names_and_falls_back_to_built() {
        let temp = tempfile::tempdir().unwrap();
        let paths = FuzzPaths {
            afe_repo: PathBuf::from("/afe"),
            python_bin: PathBuf::from("/usr/bin/python3"),
            workspace_root: temp.path().join("ws"),
            data_root: temp.path().join("ws/data"),
            source_dir: PathBuf::from("/repo"),
        };
        // An explicit name is honored even before anything is built.
        assert_eq!(engine_targets(&paths, Some("named")), vec!["named".to_string()]);
        assert!(engine_targets(&paths, None).is_empty());

        let ws = &paths.workspace_root;
        std::fs::create_dir_all(ws.join("targets/c/vhdx")).unwrap();
        std::fs::write(ws.join("targets/c/vhdx/harness.cpp"), "// h").unwrap();
        std::fs::create_dir_all(ws.join("bin/vhdx")).unwrap();
        std::fs::write(ws.join("bin/vhdx/fuzzer"), "").unwrap();
        assert_eq!(engine_targets(&paths, None), vec!["vhdx".to_string()]);
    }

    #[test]
    fn differential_options_validate_commands_and_labels() {
        fn fixture_paths() -> FuzzPaths {
            FuzzPaths {
                afe_repo: PathBuf::from("/afe"),
                python_bin: PathBuf::from("/usr/bin/python3"),
                workspace_root: PathBuf::from("/ws"),
                data_root: PathBuf::from("/ws/data"),
                source_dir: PathBuf::from("/repo"),
            }
        }

        // No commands → auto mode; the engine resolves implementations.
        let auto = FuzzDifferentialOptions::parse(&json!({"afeTarget": "tsk_bdi"})).unwrap();
        assert!(auto.commands.is_empty());
        let args = differential_args(&fixture_paths(), &auto, "tsk_bdi");
        assert!(args.contains(&"--auto".to_string()), "{args:?}");
        assert!(!args.contains(&"--command".to_string()), "{args:?}");

        // A planner-dispatched `{}` parses too: auto mode over all built targets.
        let bare = FuzzDifferentialOptions::parse(&json!({})).unwrap();
        assert_eq!(bare.afe_target, None);
        assert!(bare.commands.is_empty());

        // Explicit commands are per-target replay argvs — they need a target.
        let error = FuzzDifferentialOptions::parse(&json!({
            "commands": ["/bin/fork {input}"],
        }))
        .unwrap_err()
        .to_string();
        assert!(error.contains("afeTarget"), "{error}");

        let error = FuzzDifferentialOptions::parse(&json!({
            "afeTarget": "tsk_bdi",
            "commands": ["/bin/fork {input}", "/bin/upstream {input}"],
            "labels": ["fork"],
        }))
        .unwrap_err()
        .to_string();
        assert!(error.contains("positionally match"), "{error}");

        let options = FuzzDifferentialOptions::parse(&json!({
            "afeTarget": "tsk_bdi",
            "commands": ["/bin/fork {input}", "/bin/upstream {input}"],
            "labels": ["fork", "upstream"],
            "compare": "output",
        }))
        .unwrap();
        let args = differential_args(&fixture_paths(), &options, "tsk_bdi");
        assert!(!args.contains(&"--auto".to_string()), "{args:?}");
        assert_eq!(args.iter().filter(|a| *a == "--command").count(), 2);
        assert_eq!(args.iter().filter(|a| *a == "--label").count(), 2);
        assert!(args.windows(2).any(|w| w[0] == "--compare" && w[1] == "output"), "{args:?}");
        assert!(args.windows(2).any(|w| w[0] == "--workspace-root" && w[1] == "/ws"), "{args:?}");
    }

    #[test]
    fn campaign_round_args_thread_klee_flags_only_when_config_is_set() {
        fn fixture_paths() -> FuzzPaths {
            FuzzPaths {
                afe_repo: PathBuf::from("/afe"),
                python_bin: PathBuf::from("/usr/bin/python3"),
                workspace_root: PathBuf::from("/ws"),
                data_root: PathBuf::from("/ws/data"),
                source_dir: PathBuf::from("/repo"),
            }
        }

        // Default (no kleeConfig): today's argv, byte-for-byte, no klee flags.
        let plain = FuzzRunOptions::parse(&json!({})).unwrap();
        assert!(plain.klee_lane().is_none());
        let args = campaign_round_args(&fixture_paths(), &plain, "vhdx");
        assert!(!args.iter().any(|a| a.starts_with("--klee")), "{args:?}");
        assert_eq!(
            args,
            vec![
                "campaign-round-run", "vhdx", "--rounds", "1", "--fuzz-seconds", "600",
                "--rss-limit-mb", "2048", "--min-free-gb", "10", "--workspace-root", "/ws",
            ]
        );

        // Relative config resolves under <ws>/klee/; cadence defaults pinned.
        let relative = FuzzRunOptions::parse(&json!({"kleeConfig": "ci.json"})).unwrap();
        let args = campaign_round_args(&fixture_paths(), &relative, "vhdx");
        assert!(args.windows(2).any(|w| w[0] == "--klee-config" && w[1] == "/ws/klee/ci.json"), "{args:?}");
        assert!(args.windows(2).any(|w| w[0] == "--klee-every" && w[1] == "4"), "{args:?}");
        assert!(args.windows(2).any(|w| w[0] == "--klee-seconds" && w[1] == "900"), "{args:?}");

        // Absolute config passes through verbatim; snake aliases + explicit
        // cadence are honored.
        let explicit = FuzzRunOptions::parse(&json!({
            "klee_config": "/abs/esc.ci.json", "klee_every": 2, "klee_seconds": 1800,
        }))
        .unwrap();
        let args = campaign_round_args(&fixture_paths(), &explicit, "vhdx");
        assert!(args.windows(2).any(|w| w[0] == "--klee-config" && w[1] == "/abs/esc.ci.json"), "{args:?}");
        assert!(args.windows(2).any(|w| w[0] == "--klee-every" && w[1] == "2"), "{args:?}");
        assert!(args.windows(2).any(|w| w[0] == "--klee-seconds" && w[1] == "1800"), "{args:?}");
    }

    #[test]
    fn unprovisionable_engine_is_an_explicit_skip_and_invalid_repo_is_an_error() {
        let temp = tempfile::tempdir().unwrap();
        // No afeRepo → auto-provision; a dead remote plus an uncached rev
        // keeps the attempt hermetic and makes it fail fast.
        let input = json!({
            "afeGitUrl": temp.path().join("no-remote").display().to_string(),
            "afeRev": "b".repeat(40),
        });
        match prepare_fuzz_paths(&input, temp.path()).unwrap() {
            FuzzReadiness::Skip(reason) => {
                assert!(reason.contains("auto-provisioning"), "{reason}");
                assert!(reason.contains("afeRepo"), "{reason}");
            }
            FuzzReadiness::Ready(_) => panic!("must skip when provisioning fails"),
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
    fn provision_spec_folds_options_over_the_pinned_defaults() {
        let spec = provision_spec_from_input(&json!({})).unwrap();
        assert_eq!(spec.git_url, provision::DEFAULT_AFE_GIT_URL);
        assert_eq!(spec.rev, provision::DEFAULT_AFE_REV);
        assert_eq!(spec.ssh_key, None);
        assert!(spec.cache_home.ends_with(".cache/agentic-fuzz"), "{spec:?}");

        let overridden = provision_spec_from_input(&json!({
            "afeGitUrl": "file:///srv/afe.git",
            "afeRev": "c".repeat(40),
            "afeGitSshKey": "/keys/deploy",
        }))
        .unwrap();
        assert_eq!(overridden.git_url, "file:///srv/afe.git");
        assert_eq!(overridden.rev, "c".repeat(40));
        assert_eq!(overridden.ssh_key, Some(PathBuf::from("/keys/deploy")));
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

        // KLEE snake-case aliases canonicalize at the registry boundary and
        // parse into the options the round args consume.
        let prepared = registry
            .prepare_tool_input(
                "fuzz:run",
                json!({"shard": "vhdx", "klee_config": "ci.json", "klee_every": 2}),
                None,
            )
            .unwrap();
        assert_eq!(prepared["kleeConfig"], json!("ci.json"));
        assert_eq!(prepared["kleeEvery"], json!(2));
        let options = FuzzRunOptions::parse(&prepared).unwrap();
        assert_eq!(options.klee_config.as_deref(), Some("ci.json"));
        assert_eq!(options.klee_lane().map(|lane| (lane.every, lane.seconds)), Some((2, 900)));
    }

    /// The planner journey dispatches `{}` for the sweep and differential
    /// tasks; prepare must accept the empty input and fold descriptor
    /// defaults instead of demanding afeTarget/commands.
    #[test]
    fn planner_empty_input_prepares_for_sweep_and_differential() {
        let registry = crate::modules::ModuleRegistry::with_v2_builtins_without_optional_adapters();

        for tool in ["fuzz:sweep", "fuzz:differential"] {
            let prepared = registry
                .prepare_tool_input(tool, json!({}), None)
                .unwrap_or_else(|error| panic!("{tool}: {error:#}"));
            assert!(prepared.get("afeTarget").is_none(), "{tool}: {prepared}");
        }

        let sweep = registry.prepare_tool_input("fuzz:sweep", json!({}), None).unwrap();
        assert_eq!(sweep["sanitizer"], json!("msan"));
        FuzzSweepOptions::parse(&sweep).unwrap();
        let differential = registry
            .prepare_tool_input("fuzz:differential", json!({}), None)
            .unwrap();
        FuzzDifferentialOptions::parse(&differential).unwrap();
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
            buildable: ["a".to_string()].into_iter().collect(),
            built: ["a".to_string()].into_iter().collect(),
            workorders: vec!["b".into()],
        };
        let output = fuzz_status_output(Path::new("/ws"), &probe, Some((2, 5)));
        assert!(output.contains("2 target(s), 1 built, 1 workorder(s)"), "{output}");
        assert!(output.contains("2/5 verified"), "{output}");
    }
}
