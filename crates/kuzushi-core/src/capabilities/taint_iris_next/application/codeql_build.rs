use super::*;
use std::time::Duration;

/// Result of running the `taint-iris-next:codeql-db` tool. A success carries
/// the path of the newly-built DB so the hunt can pick it up.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CodeqlBuildReport {
    pub(crate) target: String,
    pub(crate) status: String,
    pub(crate) db_path: String,
    pub(crate) language: String,
    pub(crate) build_command: String,
    pub(crate) build_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) stderr_excerpt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) parse_error: Option<String>,
    #[serde(skip)]
    pub(crate) cost_usd: f64,
    #[serde(skip)]
    pub(crate) cost_usd_exact: bool,
    #[serde(skip)]
    pub(crate) ok: bool,
}

impl CodeqlBuildReport {
    pub(crate) fn to_tool_json(&self) -> Value {
        let mut output = json!({
            "ok": self.ok,
            "output": render_codeql_build_summary(self),
            "data": serde_json::to_value(self).unwrap_or(Value::Null),
        });
        let observed = RuntimeCost::from_usd(self.cost_usd, "CodeQL build plan cost")
            .expect("CodeQL build runtime response cost was checked");
        let cost = if self.cost_usd_exact {
            RuntimeCostReport::known(observed)
        } else {
            RuntimeCostReport::incomplete(observed)
        };
        crate::module_result::apply_runtime_cost_report(&mut output, cost);
        output
    }
}

fn render_codeql_build_summary(report: &CodeqlBuildReport) -> String {
    let mut lines = vec![
        format!("taint-iris-next:codeql-db — {}", report.status),
        format!("target: {}", report.target),
        format!("db:     {}", report.db_path),
        format!("language: {}", report.language),
        format!("build mode: {}", report.build_mode),
        format!("build command: {}", report.build_command),
    ];
    append_codeql_stderr_summary(&mut lines, report.stderr_excerpt.as_deref());
    append_codeql_parse_error(&mut lines, report.parse_error.as_deref());
    lines.join("\n")
}

fn append_codeql_stderr_summary(lines: &mut Vec<String>, stderr: Option<&str>) {
    let Some(stderr) = stderr.filter(|value| !value.trim().is_empty()) else {
        return;
    };
    lines.push(String::new());
    lines.push("--- codeql stderr (last 600 chars) ---".to_string());
    lines.push(stderr.to_string());
}

fn append_codeql_parse_error(lines: &mut Vec<String>, error: Option<&str>) {
    if let Some(error) = error {
        lines.push(format!("agent parse error: {error}"));
    }
}

/// Decision the agent returns: which language to extract, how to build, and
/// whether tracing is required (build-mode=none works for languages where
/// CodeQL doesn't need to observe a compiler — Python, JavaScript, Ruby).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CodeqlBuildPlan {
    #[serde(default)]
    language: String,
    #[serde(default, alias = "build_mode")]
    build_mode: String,
    #[serde(default, alias = "build_command")]
    build_command: String,
    #[serde(default)]
    #[serde(rename = "rationale")]
    _rationale: String,
}

/// Drive an LLM-picked build, wrap it in `codeql database create`, and
/// produce a CodeQL DB at `<target>/.kuzushi/codeql-db` that the
/// `codeql` backend can immediately consume. This removes the manual
/// `./configure && make` step from the operator's path: the agent reads
/// the codebase and decides what command extracts C/C++ facts (or
/// declares "build-mode=none" for tracing-free languages).
pub(crate) fn run_codeql_build_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<CodeqlBuildReport> {
    let target = resolve_codeql_build_target(input, ctx)?;
    let runtime = require_taint_iris_next_runtime(runtime)?;
    let model = require_taint_iris_next_model(input, ctx)?;
    let system_prompt = codeql_build_system_prompt(input)?;
    let launcher = require_codeql_launcher()?;
    let (detected_languages, response) =
        request_codeql_build_plan(runtime, model, &target, system_prompt)?;
    let cost = response.checked_cost_report()?;
    let plan = decode_codeql_build_plan(&response)?;
    let language = resolved_codeql_language(&plan, &detected_languages);
    let build_mode = resolved_codeql_build_mode(&plan, &language);
    let db_path = prepare_codeql_db_path(&target)?;
    let source_commit = crate::remediation::patch::repository_source_commit(input)?;
    let timeout = codeql_build_timeout(input)?;
    let (build_command, output) = execute_codeql_build(
        &launcher,
        &target,
        &db_path,
        &language,
        &build_mode,
        &plan,
        &source_commit,
        ctx.cancellation,
        timeout,
    )?;
    let ok = output.status.success() && db_built(&db_path);
    let details = codeql_build_details(language, build_command, build_mode, &output);
    Ok(codeql_build_report(
        &target, &db_path, details, cost, ok,
    ))
}

fn codeql_build_system_prompt(input: &Value) -> Result<String> {
    Ok(optional_taint_next_string(
        input,
        &["TAINT_IRIS_NEXT_CODEQL_BUILD_PROMPT"],
    )?
    .unwrap_or_else(|| TAINT_IRIS_NEXT_CODEQL_BUILD_SYSTEM_PROMPT.to_string()))
}

struct CodeqlBuildDetails {
    language: String,
    build_command: String,
    build_mode: String,
    stderr_excerpt: String,
    status: std::process::ExitStatus,
}

fn codeql_build_details(
    language: String,
    build_command: String,
    build_mode: String,
    output: &std::process::Output,
) -> CodeqlBuildDetails {
    CodeqlBuildDetails {
        language,
        build_command,
        build_mode,
        stderr_excerpt: codeql_stderr_excerpt(&output.stderr),
        status: output.status,
    }
}

fn codeql_build_report(
    target: &Path,
    db_path: &Path,
    details: CodeqlBuildDetails,
    cost: RuntimeCostReport,
    ok: bool,
) -> CodeqlBuildReport {
    CodeqlBuildReport {
        target: target.display().to_string(),
        status: codeql_build_status(ok, details.status),
        db_path: db_path.display().to_string(),
        language: details.language,
        build_command: details.build_command,
        build_mode: details.build_mode,
        stderr_excerpt: (!details.stderr_excerpt.trim().is_empty())
            .then_some(details.stderr_excerpt),
        parse_error: None,
        cost_usd: cost.observed_usd(),
        cost_usd_exact: cost.is_complete(),
        ok,
    }
}

fn request_codeql_build_plan(
    runtime: &dyn AgentRuntime,
    model: String,
    target: &Path,
    system_prompt: String,
) -> Result<(Vec<String>, AgentQueryResponse)> {
    let languages = detect_taint_iris_next_languages(target)?;
    let prompt = build_codeql_build_prompt(
        target,
        &languages,
        &top_level_listing(target),
        &manifest_keywords(target),
    );
    let response = query_codeql_build_plan(runtime, model, target, system_prompt, prompt)?;
    Ok((languages, response))
}

fn execute_codeql_build(
    launcher: &Path,
    target: &Path,
    db_path: &Path,
    language: &str,
    build_mode: &str,
    plan: &CodeqlBuildPlan,
    source_commit: &str,
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
) -> Result<(String, std::process::Output)> {
    let (build_command, strategy) = isolated_codeql_strategy(plan, build_mode);
    let output = crate::codeql_repository_execution::run_codeql_repository_build(
        crate::codeql_repository_execution::CodeqlRepositoryBuild {
            source_root: target,
            source_commit,
            destination: db_path,
            launcher,
            language,
            strategy,
            cancellation,
            timeout,
        },
    )?;
    Ok((build_command, output))
}

fn isolated_codeql_strategy<'a>(
    plan: &'a CodeqlBuildPlan,
    build_mode: &'a str,
) -> (
    String,
    crate::codeql_repository_execution::CodeqlBuildStrategy<'a>,
) {
    if build_mode == "none" {
        return (
            String::new(),
            crate::codeql_repository_execution::CodeqlBuildStrategy::BuildMode("none"),
        );
    }
    let command = codeql_build_command(plan);
    let strategy = crate::codeql_repository_execution::CodeqlBuildStrategy::Manual(
        plan.build_command.trim(),
    );
    (command, strategy)
}

fn codeql_build_timeout(input: &Value) -> Result<Duration> {
    crate::bounded_subprocess::timeout_from_input(
        input,
        &["timeoutMs", "timeout_ms"],
        crate::codeql_repository_execution::DEFAULT_CODEQL_REPOSITORY_TIMEOUT_MS,
        crate::codeql_repository_execution::MAX_CODEQL_REPOSITORY_TIMEOUT_MS,
        "taint-iris-next:codeql-db timeoutMs",
    )
}

fn resolve_codeql_build_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let requested = resolve_tool_target(input, ctx)?;
    let target = std::fs::canonicalize(&requested)
        .with_context(|| format!("could not resolve CodeQL target {}", requested.display()))?;
    if !target.is_dir() {
        anyhow::bail!(
            "taint-iris-next:codeql-db target is not a directory: {}",
            target.display()
        );
    }
    Ok(target)
}

fn require_codeql_launcher() -> Result<PathBuf> {
    codeql_launcher_path().ok_or_else(|| {
        anyhow::anyhow!(
            "taint-iris-next:codeql-db requires the codeql CLI on PATH (or set KUZUSHI_CODEQL_BIN)"
        )
    })
}

fn query_codeql_build_plan(
    runtime: &dyn AgentRuntime,
    model: String,
    target: &Path,
    system_prompt: String,
    prompt: String,
) -> Result<AgentQueryResponse> {
    crate::runtime::query_blocking_checked(runtime, AgentQueryRequest::new(
        model,
        target.to_path_buf(),
        system_prompt,
        prompt,
    ))
}

fn decode_codeql_build_plan(response: &AgentQueryResponse) -> Result<CodeqlBuildPlan> {
    let raw = raw_codeql_build_plan(response)
        .context("taint-iris-next:codeql-db agent did not return a JSON build plan")?;
    let plan: CodeqlBuildPlan = serde_json::from_value(raw)
        .context("taint-iris-next:codeql-db agent returned an invalid build plan")?;
    validate_codeql_build_plan(&plan)?;
    Ok(plan)
}

fn validate_codeql_build_plan(plan: &CodeqlBuildPlan) -> Result<()> {
    let language = plan.language.trim().to_ascii_lowercase();
    anyhow::ensure!(
        matches!(
            language.as_str(),
            "cpp" | "python" | "javascript" | "java" | "go" | "ruby" | "csharp"
        ),
        "taint-iris-next:codeql-db plan has unsupported language {:?}",
        plan.language
    );
    let build_mode = plan.build_mode.trim().to_ascii_lowercase();
    anyhow::ensure!(
        matches!(build_mode.as_str(), "none" | "manual"),
        "taint-iris-next:codeql-db plan has unsupported buildMode {:?}",
        plan.build_mode
    );
    anyhow::ensure!(
        build_mode == "none" || !plan.build_command.trim().is_empty(),
        "taint-iris-next:codeql-db manual plan requires a non-empty buildCommand"
    );
    Ok(())
}

fn raw_codeql_build_plan(response: &AgentQueryResponse) -> Option<Value> {
    response
        .structured
        .clone()
        .or_else(|| parse_json_object_from_agent_text(&response.text).ok())
        .or_else(|| serde_json::from_str::<Value>(response.text.trim()).ok())
}

fn resolved_codeql_language(plan: &CodeqlBuildPlan, detected_languages: &[String]) -> String {
    let language = plan.language.trim();
    if language.is_empty() {
        primary_codeql_language(detected_languages)
    } else {
        language.to_lowercase()
    }
}

fn resolved_codeql_build_mode(plan: &CodeqlBuildPlan, language: &str) -> String {
    let build_mode = plan.build_mode.trim();
    if build_mode.is_empty() {
        default_build_mode(language)
    } else {
        build_mode.to_lowercase()
    }
}

fn prepare_codeql_db_path(target: &Path) -> Result<PathBuf> {
    let relative = Path::new(".kuzushi/codeql-db");
    crate::workspace::prepare_workspace_output_path(target, relative)
}

fn codeql_build_command(plan: &CodeqlBuildPlan) -> String {
    plan.build_command.trim().to_string()
}

fn codeql_stderr_excerpt(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

fn codeql_build_status(ok: bool, status: std::process::ExitStatus) -> String {
    if ok {
        "built".to_string()
    } else {
        format!("build-failed (exit {status})")
    }
}

pub(crate) const TAINT_IRIS_NEXT_CODEQL_BUILD_SYSTEM_PROMPT: &str =
    "You decide how kuzushi should build a CodeQL database for a target \
codebase. Read the directory listing + manifest excerpts and pick the \
right CodeQL language plus the single shell command that completes a \
clean build of that codebase end-to-end. \
Reply only with strict JSON of the shape: \
{\"language\":\"cpp\",\"buildMode\":\"manual\",\"buildCommand\":\"./configure ... && make -j4\",\"rationale\":\"why\"}. \
language ∈ {cpp, python, javascript, java, go, ruby, csharp}. \
buildMode is `none` for languages CodeQL extracts without compiling \
(python, javascript, ruby, go in --build-mode=none mode); use `manual` \
otherwise. When buildMode is `none`, set buildCommand to \"\". \
For C/C++, prefer the project's own build entrypoint and disable \
optional dependencies that complicate the build (e.g. for postgres \
prefer `./configure --without-icu --without-readline --without-zlib \
--without-openssl --without-llvm && make -j4 -s`). For npm projects \
prefer `npm ci --ignore-scripts && npm run build` if a build script \
exists, else just install. For Cargo, `cargo build --release`. For \
Maven, `mvn -B -DskipTests package`. Do NOT run tests. Do NOT clean \
between steps unnecessarily.";

fn build_codeql_build_prompt(
    target: &Path,
    languages: &[String],
    top_level: &[String],
    manifest_excerpt: &str,
) -> String {
    let manifest = if manifest_excerpt.len() > 6_000 {
        format!("{}\n... (truncated)", &manifest_excerpt[..6_000])
    } else {
        manifest_excerpt.to_string()
    };
    [
        "## Target".to_string(),
        format!("path: {}", target.display()),
        format!(
            "detected languages: {}",
            if languages.is_empty() {
                "<unknown>".to_string()
            } else {
                languages.join(", ")
            }
        ),
        String::new(),
        "## Top-level entries (alphabetical, capped at 100)".to_string(),
        top_level.join("\n"),
        String::new(),
        "## Manifest / configure / build-system files (excerpt)".to_string(),
        manifest,
        String::new(),
        "## Output Contract".to_string(),
        "Return strict JSON: {\"language\":...,\"buildMode\":...,\"buildCommand\":...,\"rationale\":...}. Pick exactly one language + build command. The command runs from the target's root directory."
            .to_string(),
    ]
    .join("\n")
}

fn top_level_listing(target: &Path) -> Vec<String> {
    let Ok(read_dir) = std::fs::read_dir(target) else {
        return Vec::new();
    };
    let mut entries: Vec<String> = read_dir
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| !name.starts_with('.') || name == ".kuzushi")
        .collect();
    entries.sort();
    entries.truncate(100);
    entries
}

fn manifest_keywords(target: &Path) -> String {
    let manifest_files = [
        "configure",
        "configure.ac",
        "Makefile",
        "GNUmakefile",
        "CMakeLists.txt",
        "meson.build",
        "package.json",
        "pyproject.toml",
        "setup.py",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
        "build.sbt",
    ];
    let mut parts = Vec::new();
    for name in manifest_files {
        let path = target.join(name);
        if let Ok(Some(raw)) =
            crate::bounded_file::read_source_text_prefix_within(target, &path, 64 * 1024)
        {
            let truncated: String = raw.chars().take(2_000).collect();
            parts.push(format!("--- {name} (first 2KB) ---\n{truncated}"));
        }
    }
    parts.join("\n\n")
}

fn primary_codeql_language(detected: &[String]) -> String {
    for candidate in [
        "cpp",
        "c",
        "java",
        "csharp",
        "go",
        "ruby",
        "python",
        "javascript",
        "typescript",
    ] {
        if detected.iter().any(|lang| lang == candidate) {
            return match candidate {
                "c" => "cpp".to_string(),
                "typescript" => "javascript".to_string(),
                other => other.to_string(),
            };
        }
    }
    "cpp".to_string()
}

fn default_build_mode(language: &str) -> String {
    match language {
        "python" | "javascript" | "ruby" | "go" => "none".to_string(),
        _ => "manual".to_string(),
    }
}

fn db_built(path: &Path) -> bool {
    crate::codeql_repository_execution::codeql_database_is_valid(path)
}

/// Has a complete CodeQL DB been built at the standard kuzushi path?
/// Used by the prereq chain to decide whether to invoke the build tool.
#[cfg(test)]
pub(crate) fn has_codeql_db(repo_root: &Path) -> bool {
    let path = crate::workspace::workspace_codeql_db_path(repo_root);
    path.is_dir() && db_built(&path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::TriageOutcome;
    use crate::runtime::TriageRequest;
    use crate::workspace::WorkspaceTarget;
    use std::process::Command;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct BuildPlanRuntime;

    impl AgentRuntime for BuildPlanRuntime {
        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            Ok(AgentQueryResponse {
                structured: Some(json!({
                    "language": "cpp",
                    "buildMode": "manual",
                    "buildCommand": "printf isolated > source-side-effect.txt",
                    "rationale": "unit test"
                })),
                cost_usd: 0.02,
                ..AgentQueryResponse::default()
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            anyhow::bail!("not used by codeql build tests")
        }
    }

    struct CapturingBuildPlanRuntime {
        requests: Mutex<Vec<AgentQueryRequest>>,
    }

    impl CapturingBuildPlanRuntime {
        fn new() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl AgentRuntime for CapturingBuildPlanRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.requests.lock().unwrap().push(request);
            Ok(AgentQueryResponse::default())
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            anyhow::bail!("not used by CodeQL prompt tests")
        }
    }

    #[test]
    fn codeql_build_query_uses_declared_prompt_override() {
        let runtime = CapturingBuildPlanRuntime::new();

        query_codeql_build_plan(
            &runtime,
            "openai:test".to_string(),
            std::path::Path::new("/tmp/codeql-target"),
            "custom CodeQL planner".to_string(),
            "repository facts".to_string(),
        )
        .unwrap();

        let requests = runtime.requests.lock().unwrap();
        assert_eq!(requests[0].system_prompt, "custom CodeQL planner");
    }

    #[test]
    fn primary_codeql_language_prefers_cpp_then_python() {
        assert_eq!(
            primary_codeql_language(&["c".to_string(), "python".to_string()]),
            "cpp"
        );
        assert_eq!(primary_codeql_language(&["python".to_string()]), "python");
        assert_eq!(
            primary_codeql_language(&["typescript".to_string()]),
            "javascript"
        );
        assert_eq!(primary_codeql_language(&[]), "cpp");
    }

    #[test]
    fn default_build_mode_is_none_for_extracted_languages() {
        assert_eq!(default_build_mode("python"), "none");
        assert_eq!(default_build_mode("javascript"), "none");
        assert_eq!(default_build_mode("cpp"), "manual");
        assert_eq!(default_build_mode("java"), "manual");
    }

    #[test]
    fn malformed_agent_plan_is_not_replaced_with_a_build_command() {
        let response = AgentQueryResponse {
            text: "not json".to_string(),
            ..AgentQueryResponse::default()
        };

        let error = decode_codeql_build_plan(&response).unwrap_err().to_string();

        assert!(error.contains("did not return a JSON build plan"));
    }

    #[test]
    fn agent_plan_rejects_unsupported_execution_policy() {
        let response = AgentQueryResponse {
            structured: Some(json!({
                "language": "cpp",
                "buildMode": "magic",
                "buildCommand": "make"
            })),
            ..AgentQueryResponse::default()
        };

        let error = decode_codeql_build_plan(&response).unwrap_err().to_string();

        assert!(error.contains("unsupported buildMode"));
    }

    #[test]
    fn db_built_only_when_yaml_and_db_subdir_present() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("codeql-db");
        std::fs::create_dir_all(&path).unwrap();
        assert!(!db_built(&path));
        std::fs::write(path.join("codeql-database.yml"), "...").unwrap();
        assert!(!db_built(&path));
        std::fs::create_dir_all(path.join("db-cpp")).unwrap();
        assert!(db_built(&path));
    }

    #[test]
    fn has_codeql_db_false_for_empty_dir() {
        let temp = tempdir().unwrap();
        std::fs::create_dir_all(crate::workspace::workspace_codeql_db_path(temp.path())).unwrap();
        assert!(!has_codeql_db(temp.path()));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_codeql_db_rejects_symlink_without_touching_destination() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::create_dir(workspace.path().join(".kuzushi")).unwrap();
        std::fs::write(outside.path().join("sentinel"), "keep").unwrap();
        symlink(
            outside.path(),
            crate::workspace::workspace_codeql_db_path(workspace.path()),
        )
        .unwrap();

        assert!(prepare_codeql_db_path(workspace.path()).is_err());
        assert_eq!(
            std::fs::read_to_string(outside.path().join("sentinel")).unwrap(),
            "keep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn manifest_keywords_skip_symlinked_files_outside_target() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let outside_manifest = outside.path().join("package.json");
        std::fs::write(&outside_manifest, "OUTSIDE_CODEQL_MANIFEST_SECRET").unwrap();
        symlink(&outside_manifest, workspace.path().join("package.json")).unwrap();

        let excerpt = manifest_keywords(workspace.path());

        assert!(!excerpt.contains("OUTSIDE_CODEQL_MANIFEST_SECRET"));
        assert!(excerpt.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn run_codeql_build_report_drives_agent_plan_and_codeql_cli() {
        if !crate::remediation::patch_process_adapter::validation_network_sandbox_available() {
            return;
        }
        let _guard = crate::test_env::codeql_bin_env_lock();
        let temp = tempdir().unwrap();
        std::fs::write(temp.path().join("main.c"), "int main(void) { return 0; }\n").unwrap();
        let launcher = write_fake_codeql_build_script(temp.path());
        initialize_codeql_test_repository(temp.path());
        let previous = set_codeql_bin_for_test(&launcher);
        let config = codeql_build_test_config();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let ctx = codeql_build_test_context(&config, &workspace);
        let mut input = json!({"target": temp.path().display().to_string()});
        crate::remediation::patch::bind_repository_source_snapshot(temp.path(), &mut input)
            .unwrap();

        let report = run_codeql_build_report(&input, &ctx, Some(&BuildPlanRuntime)).unwrap();

        restore_codeql_bin(previous);
        assert_codeql_build_report(report);
        assert!(!temp.path().join("source-side-effect.txt").exists());
        assert!(crate::codeql_repository_execution::codeql_database_is_valid(
            &crate::workspace::workspace_codeql_db_path(temp.path())
        ));
    }

    #[cfg(unix)]
    fn write_fake_codeql_build_script(root: &Path) -> PathBuf {
        let fake_codeql = root.join("codeql");
        std::fs::write(
            &fake_codeql,
            r#"#!/usr/bin/env bash
set -euo pipefail
db="$3"
for arg in "$@"; do
  if [[ "$arg" == --command=* ]]; then
    bash -c "${arg#--command=}"
  fi
done
mkdir -p "$db/db-cpp"
printf 'primaryLanguage: cpp\n' > "$db/codeql-database.yml"
printf 'fake warning\n' >&2
"#,
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fake_codeql).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&fake_codeql, perms).unwrap();
        }
        fake_codeql
    }

    fn set_codeql_bin_for_test(fake_codeql: &Path) -> Option<std::ffi::OsString> {
        let previous = std::env::var_os("KUZUSHI_CODEQL_BIN");
        std::env::set_var("KUZUSHI_CODEQL_BIN", fake_codeql);
        previous
    }

    fn codeql_build_test_config() -> V2Config {
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config
    }

    fn codeql_build_test_context<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    fn initialize_codeql_test_repository(root: &Path) {
        run_git(root, &["init"]);
        run_git(root, &["add", "."]);
        run_git(
            root,
            &[
                "-c",
                "user.name=Kuzushi Test",
                "-c",
                "user.email=kuzushi@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        );
    }

    fn run_git(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?} failed");
    }

    fn restore_codeql_bin(previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => std::env::set_var("KUZUSHI_CODEQL_BIN", value),
            None => std::env::remove_var("KUZUSHI_CODEQL_BIN"),
        }
    }

    fn assert_codeql_build_report(report: CodeqlBuildReport) {
        assert!(report.ok);
        assert_eq!(report.status, "built");
        assert_eq!(report.language, "cpp");
        assert_eq!(report.build_mode, "manual");
        assert_eq!(
            report.build_command,
            "printf isolated > source-side-effect.txt"
        );
        assert_eq!(report.cost_usd, 0.02);
        assert!(report
            .stderr_excerpt
            .as_deref()
            .is_some_and(|stderr| stderr.contains("fake warning")));
    }
}
