use super::*;
use std::process::Command;

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
    pub(crate) ok: bool,
}

impl CodeqlBuildReport {
    pub(crate) fn to_tool_json(&self) -> Value {
        json!({
            "ok": self.ok,
            "output": render_codeql_build_summary(self),
            "data": serde_json::to_value(self).unwrap_or(Value::Null),
            "costUsd": self.cost_usd,
        })
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
    let launcher = require_codeql_launcher()?;

    // Ask the agent which build command to run. The plan stage provides
    // enough context (top-level filenames + detected languages) for the
    // model to recognise common build systems: configure scripts, CMake,
    // npm/pnpm, pyproject, Cargo, Maven, Gradle, Go modules, etc.
    let detected_languages = detect_taint_iris_next_languages(&target)?;
    let top_level = top_level_listing(&target);
    let manifest_excerpt = manifest_keywords(&target);

    let prompt =
        build_codeql_build_prompt(&target, &detected_languages, &top_level, &manifest_excerpt);

    let response = query_codeql_build_plan(runtime, model, &target, prompt)?;
    let cost_usd = response.cost_usd;
    let (plan, parse_error) = decode_codeql_build_plan(&response, &detected_languages);

    let language = resolved_codeql_language(&plan, &detected_languages);
    let build_mode = resolved_codeql_build_mode(&plan, &language);
    let db_path = prepare_codeql_db_path(&target);

    let mut cmd = codeql_database_create_command(&launcher, &db_path, &target, &language);
    let build_command = attach_codeql_build_strategy(&mut cmd, &target, &plan, &build_mode)?;

    let output = run_codeql_create_command(cmd, &launcher)?;
    let stderr_excerpt = codeql_stderr_excerpt(&output.stderr);

    let ok = output.status.success() && db_built(&db_path);
    Ok(CodeqlBuildReport {
        target: target.display().to_string(),
        status: codeql_build_status(ok, output.status),
        db_path: db_path.display().to_string(),
        language,
        build_command,
        build_mode,
        stderr_excerpt: (!stderr_excerpt.trim().is_empty()).then_some(stderr_excerpt),
        parse_error,
        cost_usd,
        ok,
    })
}

fn resolve_codeql_build_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let target = resolve_tool_target(input, ctx)?;
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
    prompt: String,
) -> Result<AgentQueryResponse> {
    runtime.query_blocking(AgentQueryRequest::new(
        model,
        target.to_path_buf(),
        TAINT_IRIS_NEXT_CODEQL_BUILD_SYSTEM_PROMPT.to_string(),
        prompt,
    ))
}

fn decode_codeql_build_plan(
    response: &AgentQueryResponse,
    detected_languages: &[String],
) -> (CodeqlBuildPlan, Option<String>) {
    match raw_codeql_build_plan(response)
        .as_ref()
        .map(|value| serde_json::from_value::<CodeqlBuildPlan>(value.clone()))
    {
        Some(Ok(plan)) => (plan, None),
        Some(Err(error)) => (default_plan(detected_languages), Some(error.to_string())),
        None => (
            default_plan(detected_languages),
            Some("agent did not return a JSON build plan".to_string()),
        ),
    }
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

fn prepare_codeql_db_path(target: &Path) -> PathBuf {
    let db_path = crate::workspace::workspace_codeql_db_path(target);
    let _ = std::fs::remove_dir_all(&db_path);
    db_path
}

fn codeql_database_create_command(
    launcher: &Path,
    db_path: &Path,
    target: &Path,
    language: &str,
) -> Command {
    let mut cmd = Command::new(launcher);
    cmd.arg("database").arg("create").arg(db_path);
    cmd.arg(format!("--language={language}"));
    cmd.arg(format!("--source-root={}", target.display()));
    cmd.arg("--overwrite");
    cmd
}

fn attach_codeql_build_strategy(
    cmd: &mut Command,
    target: &Path,
    plan: &CodeqlBuildPlan,
    build_mode: &str,
) -> Result<String> {
    if build_mode == "none" {
        cmd.arg("--build-mode=none");
        return Ok(String::new());
    }
    let raw = codeql_build_command(plan);
    let script_path = write_codeql_build_script(target, &raw)?;
    cmd.arg(format!("--command=bash {}", script_path.display()));
    Ok(raw)
}

fn codeql_build_command(plan: &CodeqlBuildPlan) -> String {
    let build_command = plan.build_command.trim();
    if build_command.is_empty() {
        "make".to_string()
    } else {
        build_command.to_string()
    }
}

fn write_codeql_build_script(target: &Path, raw: &str) -> Result<PathBuf> {
    // CodeQL's `--command` flag execs a single command directly. A wrapper
    // script lets bash interpret shell operators while CodeQL traces the build.
    let script_path = taint_iris_next_codeql_build_script_path(target);
    let script_dir = script_path
        .parent()
        .context("could not resolve CodeQL build script parent")?;
    std::fs::create_dir_all(&script_dir)
        .with_context(|| format!("could not create {}", script_dir.display()))?;
    let script_body =
        format!("#!/usr/bin/env bash\nset -euo pipefail\ncd \"$(dirname \"$0\")/..\"\n{raw}\n");
    std::fs::write(&script_path, script_body)
        .with_context(|| format!("could not write {}", script_path.display()))?;
    make_codeql_build_script_executable(&script_path);
    Ok(script_path)
}

#[cfg(unix)]
fn make_codeql_build_script_executable(script_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(metadata) = std::fs::metadata(script_path) else {
        return;
    };
    let mut perms = metadata.permissions();
    perms.set_mode(0o755);
    let _ = std::fs::set_permissions(script_path, perms);
}

#[cfg(not(unix))]
fn make_codeql_build_script_executable(_script_path: &Path) {}

fn run_codeql_create_command(mut cmd: Command, launcher: &Path) -> Result<std::process::Output> {
    cmd.output()
        .with_context(|| format!("could not invoke codeql at {}", launcher.display()))
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

const TAINT_IRIS_NEXT_CODEQL_BUILD_SYSTEM_PROMPT: &str =
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
        if let Ok(raw) = std::fs::read_to_string(&path) {
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

fn default_plan(detected: &[String]) -> CodeqlBuildPlan {
    let language = primary_codeql_language(detected);
    let build_mode = default_build_mode(&language);
    CodeqlBuildPlan {
        language: language.clone(),
        build_mode: build_mode.clone(),
        build_command: if build_mode == "none" {
            String::new()
        } else {
            "make".to_string()
        },
        _rationale: "fallback default — agent did not return a usable plan".to_string(),
    }
}

fn db_built(path: &Path) -> bool {
    let yaml_present = path.join("codeql-database.yml").exists();
    let any_db_dir = std::fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .any(|entry| entry.file_name().to_string_lossy().starts_with("db-"))
        })
        .unwrap_or(false);
    yaml_present && any_db_dir
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
    use tempfile::tempdir;

    struct BuildPlanRuntime;

    impl AgentRuntime for BuildPlanRuntime {
        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            Ok(AgentQueryResponse {
                structured: Some(json!({
                    "language": "cpp",
                    "buildMode": "none",
                    "buildCommand": "",
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

    #[test]
    #[cfg(unix)]
    fn run_codeql_build_report_drives_agent_plan_and_codeql_cli() {
        let _guard = crate::test_env::codeql_bin_env_lock();
        let temp = tempdir().unwrap();
        std::fs::write(temp.path().join("main.c"), "int main(void) { return 0; }\n").unwrap();
        let previous = set_codeql_bin_for_test(&write_fake_codeql_build_script(temp.path()));
        let config = codeql_build_test_config();
        let ctx = codeql_build_test_context(&config);

        let report = run_codeql_build_report(
            &json!({"target": temp.path().display().to_string()}),
            &ctx,
            Some(&BuildPlanRuntime),
        )
        .unwrap();

        restore_codeql_bin(previous);
        assert_codeql_build_report(report);
    }

    #[cfg(unix)]
    fn write_fake_codeql_build_script(root: &Path) -> PathBuf {
        let fake_codeql = root.join("codeql");
        std::fs::write(
            &fake_codeql,
            r#"#!/usr/bin/env bash
set -euo pipefail
db="$3"
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

    fn codeql_build_test_context(config: &V2Config) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config,
            workspace: None,
            findings_store: None,
            trace: None,
        }
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
        assert_eq!(report.build_mode, "none");
        assert_eq!(report.cost_usd, 0.02);
        assert!(report
            .stderr_excerpt
            .as_deref()
            .is_some_and(|stderr| stderr.contains("fake warning")));
    }
}
