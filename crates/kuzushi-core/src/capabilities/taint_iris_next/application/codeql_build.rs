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
    if let Some(stderr) = &report.stderr_excerpt {
        if !stderr.trim().is_empty() {
            lines.push(String::new());
            lines.push("--- codeql stderr (last 600 chars) ---".to_string());
            lines.push(stderr.clone());
        }
    }
    if let Some(error) = &report.parse_error {
        lines.push(format!("agent parse error: {error}"));
    }
    lines.join("\n")
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
    let target = resolve_tool_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "taint-iris-next:codeql-db target is not a directory: {}",
            target.display()
        );
    }

    let runtime = require_taint_iris_next_runtime(runtime)?;
    let model = require_taint_iris_next_model(input, ctx)?;

    if !codeql_available() {
        anyhow::bail!(
            "taint-iris-next:codeql-db requires the codeql CLI on PATH (or set KUZUSHI_CODEQL_BIN)"
        );
    }
    let Some(launcher) = codeql_launcher_path() else {
        anyhow::bail!("codeql launcher disappeared between probe and run");
    };

    // Ask the agent which build command to run. The plan stage provides
    // enough context (top-level filenames + detected languages) for the
    // model to recognise common build systems: configure scripts, CMake,
    // npm/pnpm, pyproject, Cargo, Maven, Gradle, Go modules, etc.
    let detected_languages = detect_taint_iris_next_languages(&target)?;
    let top_level = top_level_listing(&target);
    let manifest_excerpt = manifest_keywords(&target);

    let prompt =
        build_codeql_build_prompt(&target, &detected_languages, &top_level, &manifest_excerpt);

    let response = runtime.query_blocking(AgentQueryRequest::new(
        model.clone(),
        target.clone(),
        TAINT_IRIS_NEXT_CODEQL_BUILD_SYSTEM_PROMPT.to_string(),
        prompt,
    ))?;
    let cost_usd = response.cost_usd;

    let raw = response
        .structured
        .clone()
        .or_else(|| parse_json_object_from_agent_text(&response.text).ok())
        .or_else(|| serde_json::from_str::<Value>(response.text.trim()).ok());

    let (plan, parse_error) = match raw
        .as_ref()
        .map(|value| serde_json::from_value::<CodeqlBuildPlan>(value.clone()))
    {
        Some(Ok(plan)) => (plan, None),
        Some(Err(error)) => (default_plan(&detected_languages), Some(error.to_string())),
        None => (
            default_plan(&detected_languages),
            Some("agent did not return a JSON build plan".to_string()),
        ),
    };

    let language = if plan.language.trim().is_empty() {
        primary_codeql_language(&detected_languages)
    } else {
        plan.language.trim().to_lowercase()
    };
    let build_mode = if plan.build_mode.trim().is_empty() {
        default_build_mode(&language)
    } else {
        plan.build_mode.trim().to_lowercase()
    };

    let db_path = target.join(".kuzushi").join("codeql-db");
    let _ = std::fs::remove_dir_all(&db_path);

    let mut cmd = Command::new(&launcher);
    cmd.arg("database").arg("create").arg(&db_path);
    cmd.arg(format!("--language={}", language));
    cmd.arg(format!("--source-root={}", target.display()));
    cmd.arg("--overwrite");
    let build_command = if build_mode == "none" {
        cmd.arg("--build-mode=none");
        String::new()
    } else {
        // CodeQL's `--command` flag treats each invocation as a *single*
        // shell-command-like string but exec()s it directly with no shell
        // (so `&&`, pipes and env-prefixes don't work). Drop the agent's
        // build steps into a wrapper script under .kuzushi and pass that
        // script as the build command — bash interprets the script
        // contents normally and codeql traces every compiler invocation
        // along the way.
        let raw = if plan.build_command.trim().is_empty() {
            "make".to_string()
        } else {
            plan.build_command.trim().to_string()
        };
        let script_path = target.join(".kuzushi").join("codeql-build.sh");
        if let Some(parent) = script_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let script_body =
            format!("#!/usr/bin/env bash\nset -euo pipefail\ncd \"$(dirname \"$0\")/..\"\n{raw}\n");
        if std::fs::write(&script_path, script_body).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(&script_path) {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o755);
                    let _ = std::fs::set_permissions(&script_path, perms);
                }
            }
        }
        cmd.arg(format!("--command=bash {}", script_path.display()));
        raw
    };

    let output = cmd
        .output()
        .with_context(|| format!("could not invoke codeql at {}", launcher.display()))?;

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stderr_excerpt = stderr
        .lines()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");

    let ok = output.status.success() && db_built(&db_path);
    let status = if ok {
        "built".to_string()
    } else {
        format!("build-failed (exit {})", output.status)
    };

    Ok(CodeqlBuildReport {
        target: target.display().to_string(),
        status,
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
    let path = repo_root.join(".kuzushi").join("codeql-db");
    path.is_dir() && db_built(&path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
        std::fs::create_dir_all(temp.path().join(".kuzushi/codeql-db")).unwrap();
        assert!(!has_codeql_db(temp.path()));
    }
}
