use super::*;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(in crate::modules) fn cpg_module() -> BuiltinModule {
    builtin_module(
        "cpg",
        "Code Property Graph",
        ModuleKind::Intel,
        "Build experimental in-process source graphs for structural inspection. Source \
         collection still needs aggregate read limits and cooperative cancellation.",
        vec![cpg_build_tool()],
        vec![dag("cpg:build", "cpg", &["context:build"])],
    )
    .labs()
}

fn cpg_build_tool() -> ToolDescriptor {
    tool_with_options(
        "cpg:build",
        "Build and reuse experimental source graphs below .kuzushi/cpg-rs/. Prefer a \
         small explicit subdir. The file cap covers frontend construction; source \
         reads and enumeration lack aggregate limits. Graphs are auxiliary Map evidence.",
        cpg_build_options(),
    )
    .with_policy(workspace_policy(
        ToolPhase::Map,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Optional,
    ))
    .without_phase_result()
}

fn cpg_build_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        opt(
            "languages",
            OptionType::String,
            "Comma-separated language list to build graphs for (e.g. `go,python`). \
             Defaults to auto-detection over the target's source files. Supported: \
             c, cpp, go, java, javascript, python, ruby, rust, scala, typescript.",
        )
        .aliases(&["language", "langs"]),
        opt(
            "importPath",
            OptionType::Path,
            "Reuse a prebuilt cpg-rs graph instead of building: the file is format-checked and \
             copied to the canonical .kuzushi/cpg-rs/ location. The file name must keep the \
             engine convention `<lang>.v<shape>.cpg` (or `<key>.<lang>.v<shape>.cpg` from the \
             engine's own cache) so the language and shape version are explicit.",
        )
        .external_read()
        .aliases(&["import_path", "existingCpg", "existing_cpg"]),
        cpg_build_subdir_option(),
        opt(
            "maxSourceFiles",
            OptionType::Int,
            "Refuse builds whose in-scope corpus exceeds this many source files (default \
             25000). Prefer scoping with subdir over raising the cap.",
        )
        .aliases(&["max_source_files", "maxCpgSourceFiles"])
        .advanced(),
    ]
}

fn cpg_build_subdir_option() -> OptionSpec {
    opt(
        "subdir",
        OptionType::Path,
        "Relative subdirectory under the target to build graphs from. The graph still \
         lands under the target root's .kuzushi/cpg-rs/scoped/<key>/.",
    )
    .workspace_read()
    .aliases(&["targetSubdir", "target_subdir"])
    .advanced()
}

fn announce_cpg_phase(ctx: &ToolExecutionContext<'_>, kind: &str, label: &str) {
    emit_step(ctx, kind, "build", label.to_string());
}

pub(in crate::modules) fn run_cpg_build(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    if let Some(import_path) = resolve_cpg_import_path(input) {
        validate_import_options(input)?;
        return run_cpg_import(ctx, &target, &import_path);
    }
    let scope = resolve_cpg_scope(input, &target)?;
    let limits = resolve_cpg_limits(input)?;
    let languages = resolve_build_languages(input, &scope.scan_root())?;
    if languages.is_empty() {
        return Ok(no_supported_language_response(&scope.scan_root()));
    }
    announce_cpg_phase(ctx, "tool", "cpg:build start");
    let started = Instant::now();
    let outcome = build_language_graphs(ctx, &target, &scope, &limits, &languages)?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    announce_cpg_outcome(ctx, &outcome, elapsed_ms);
    cpg_build_response(&target, &scope.scan_root(), &outcome, elapsed_ms, now_ms()?)
}

fn validate_import_options(input: &Value) -> Result<()> {
    for key in ["languages", "subdir", "maxSourceFiles"] {
        anyhow::ensure!(input.get(key).is_none(),
            "cpg:build importPath cannot be combined with build option {key}; remove it before importing");
    }
    Ok(())
}

/// Build scope from the optional `subdir` input: sources come from the
/// subtree, the artifact stays under the target root's `.kuzushi`. The
/// prepared option may arrive target-absolute (workspace-read resolution);
/// both spellings normalize to a target-relative subdir.
fn resolve_cpg_scope(input: &Value, target: &Path) -> Result<kuzushi_cpg::BuildScope> {
    let subdir = input
        .get("subdir")
        .or_else(|| input.get("targetSubdir"))
        .or_else(|| input.get("target_subdir"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match subdir {
        None => Ok(kuzushi_cpg::BuildScope::whole(target)),
        Some(subdir) => {
            let relative = Path::new(subdir)
                .strip_prefix(target)
                .unwrap_or(Path::new(subdir));
            kuzushi_cpg::BuildScope::subtree(target, relative)
                .map_err(|error| anyhow::anyhow!("cpg:build subdir: {error}"))
        }
    }
}

fn resolve_cpg_limits(input: &Value) -> Result<kuzushi_cpg::BuildLimits> {
    let raw = ["maxSourceFiles", "max_source_files", "maxCpgSourceFiles"]
        .iter()
        .find_map(|key| input.get(*key));
    let Some(raw) = raw else {
        return Ok(kuzushi_cpg::BuildLimits::default());
    };
    let value = raw
        .as_u64()
        .or_else(|| raw.as_str().and_then(|text| text.trim().parse().ok()))
        .filter(|value| *value > 0)
        .context("cpg:build maxSourceFiles must be a positive integer")?;
    Ok(kuzushi_cpg::BuildLimits {
        max_source_files: value as usize,
    })
}

struct CpgBuildOutcome {
    reports: Vec<kuzushi_cpg::CpgBuildReport>,
    stop_reason: Option<String>,
}

fn build_language_graphs(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    scope: &kuzushi_cpg::BuildScope,
    limits: &kuzushi_cpg::BuildLimits,
    languages: &[&'static str],
) -> Result<CpgBuildOutcome> {
    let mut reports = Vec::new();
    for lang in languages {
        match build_language_graph(ctx, target, scope, limits, lang) {
            Ok(report) => reports.push(report),
            Err(error) => return stopped_graph_outcome(reports, error),
        }
    }
    Ok(CpgBuildOutcome {
        reports,
        stop_reason: None,
    })
}

fn build_language_graph(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    scope: &kuzushi_cpg::BuildScope,
    limits: &kuzushi_cpg::BuildLimits,
    lang: &str,
) -> Result<kuzushi_cpg::CpgBuildReport> {
    ctx.ensure_active()?;
    prepare_cpg_artifact_path(target, &scope.artifact_path(lang))?;
    announce_cpg_phase(ctx, "tool-progress", &format!("building {lang} graph"));
    let (_, report) = kuzushi_cpg::ensure_project_in(scope, lang, limits)
        .map_err(|error| anyhow::anyhow!("cpg:build {lang} failed: {error}"))?;
    announce_cpg_phase(ctx, "tool-progress", &language_report_label(&report));
    Ok(report)
}

fn stopped_graph_outcome(
    reports: Vec<kuzushi_cpg::CpgBuildReport>,
    error: anyhow::Error,
) -> Result<CpgBuildOutcome> {
    if reports.is_empty() {
        return Err(error);
    }
    Ok(CpgBuildOutcome {
        reports,
        stop_reason: Some(format!("{error:#}")),
    })
}

fn announce_cpg_outcome(
    ctx: &ToolExecutionContext<'_>,
    outcome: &CpgBuildOutcome,
    elapsed_ms: u64,
) {
    if let Some(reason) = &outcome.stop_reason {
        announce_cpg_phase(ctx, "warning", reason);
        return;
    }
    announce_cpg_phase(
        ctx,
        "done",
        &cpg_complete_label(&outcome.reports, elapsed_ms),
    );
}

fn language_report_label(report: &kuzushi_cpg::CpgBuildReport) -> String {
    let action = if report.reused_cache {
        "reused"
    } else {
        "built"
    };
    format!(
        "{} {} graph · {} source file{} · {} method{}, {} call{} · {} ms",
        action,
        report.language,
        report.source_files,
        plural_suffix(report.source_files),
        report.methods,
        plural_suffix(report.methods),
        report.calls,
        plural_suffix(report.calls),
        report.duration_ms
    )
}

fn plural_suffix(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

fn cpg_complete_label(reports: &[kuzushi_cpg::CpgBuildReport], elapsed_ms: u64) -> String {
    let langs: Vec<&str> = reports.iter().map(|r| r.language.as_str()).collect();
    format!(
        "cpg:build complete · {} graph(s): {} in {} ms · auxiliary Map evidence",
        reports.len(),
        langs.join(", "),
        elapsed_ms
    )
}

/// Resolve the languages to build: an explicit CSV option (validated against
/// the engine's supported set) or file-census auto-detection.
fn resolve_build_languages(input: &Value, target: &Path) -> Result<Vec<&'static str>> {
    let requested = input
        .get("languages")
        .or_else(|| input.get("language"))
        .or_else(|| input.get("langs"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match requested {
        Some(csv) => parse_language_csv(csv),
        None => Ok(kuzushi_cpg::detect_buildable_languages(target)),
    }
}

fn parse_language_csv(csv: &str) -> Result<Vec<&'static str>> {
    let mut languages = Vec::new();
    for raw in csv.split(',') {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        let lang = kuzushi_cpg::canonical_language(name).ok_or_else(|| {
            anyhow::anyhow!(
                "cpg:build does not support language `{name}`; supported: {}",
                kuzushi_cpg::supported_languages().join(", ")
            )
        })?;
        if !languages.contains(&lang) {
            languages.push(lang);
        }
    }
    Ok(languages)
}

fn resolve_cpg_import_path(input: &Value) -> Option<PathBuf> {
    input
        .get("importPath")
        .or_else(|| input.get("import_path"))
        .or_else(|| input.get("existingCpg"))
        .or_else(|| input.get("existing_cpg"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}

/// Import a prebuilt cpg-rs graph: validate the source and its naming
/// convention, then copy it to the canonical per-language artifact path.
fn run_cpg_import(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    import_path: &Path,
) -> Result<Value> {
    let source = open_cpg_import_source(import_path)?;
    let lang = import_language(import_path)?;
    let output_path = prepare_cpg_artifact_path(target, &kuzushi_cpg::artifact_path(target, lang))?;
    announce_cpg_phase(
        ctx,
        "tool",
        &format!(
            "cpg:build import {lang} graph from {}",
            import_path.display()
        ),
    );
    let started = Instant::now();
    let bytes = install_cpg_import(source, &output_path)?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    announce_cpg_phase(ctx, "done", &format!("cpg:build imported {lang} graph"));
    Ok(cpg_import_response(
        target,
        &output_path,
        import_path,
        lang,
        bytes,
        elapsed_ms,
        now_ms()?,
    ))
}

/// The language a graph import carries, from the engine's file-name
/// convention. Rejects names that don't parse to a supported language so a
/// wrong-language graph can't be silently installed as `c`.
fn import_language(import_path: &Path) -> Result<&'static str> {
    let name = import_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let parsed = cpg_cli_lang_of(&name);
    kuzushi_cpg::canonical_language(&parsed)
        .filter(|_| name.ends_with(&format!(".v{}.cpg", kuzushi_cpg::GRAPH_SHAPE_VERSION)))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot derive a supported language and current shape version from `{name}`; \
                 expected `<lang>.v{}.cpg` (rebuild with the current engine if the version \
                 differs)",
                kuzushi_cpg::GRAPH_SHAPE_VERSION
            )
        })
}

/// `<key>.<lang>.v<N>.cpg` or `<lang>.v<N>.cpg` → `<lang>`.
fn cpg_cli_lang_of(name: &str) -> String {
    let mut parts: Vec<&str> = name.split('.').collect();
    parts.pop(); // "cpg"
    if parts.last().is_some_and(|p| p.starts_with('v')) {
        parts.pop();
    }
    parts.pop().unwrap_or_default().to_string()
}

struct CpgImportSource {
    file: fs::File,
    bytes: u64,
}

/// A usable import source is an existing engine-decodable regular file
/// (symlinks are followed; the resolved file must still be regular).
fn open_cpg_import_source(import_path: &Path) -> Result<CpgImportSource> {
    let file = fs::File::open(import_path).with_context(|| {
        format!(
            "prebuilt CPG not found at {} — check importPath",
            import_path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .with_context(|| format!("Could not inspect prebuilt CPG {}", import_path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "prebuilt CPG {} is not a regular file",
        import_path.display()
    );
    kuzushi_cpg::validate_graph_artifact(import_path).map_err(anyhow::Error::msg)?;
    Ok(CpgImportSource {
        file,
        bytes: metadata.len(),
    })
}

fn install_cpg_import(mut source: CpgImportSource, output_path: &Path) -> Result<u64> {
    let parent = output_path.parent().context("CPG output has no parent")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("Could not stage CPG import below {}", parent.display()))?;
    let copied = std::io::copy(&mut source.file, staged.as_file_mut())?;
    anyhow::ensure!(
        copied == source.bytes,
        "prebuilt CPG copy is truncated: {copied} bytes copied of {}",
        source.bytes
    );
    staged.as_file_mut().flush()?;
    staged.as_file().sync_all()?;
    kuzushi_cpg::validate_graph_artifact(staged.path()).map_err(anyhow::Error::msg)?;
    staged.persist(output_path).map_err(|error| {
        anyhow::anyhow!(
            "Could not publish imported CPG {}: {}",
            output_path.display(),
            error.error
        )
    })?;
    Ok(copied)
}

/// Validate + create one artifact location, keeping the write inside the
/// target root's `.kuzushi` through the shared workspace guard.
fn prepare_cpg_artifact_path(target: &Path, path: &Path) -> Result<PathBuf> {
    let relative = path.strip_prefix(target).with_context(|| {
        format!(
            "CPG output {} must stay inside target {}",
            path.display(),
            target.display()
        )
    })?;
    anyhow::ensure!(
        relative.starts_with(crate::workspace::KUZUSHI_STATE_DIR),
        "CPG output {} must stay below .kuzushi",
        path.display()
    );
    crate::workspace::prepare_workspace_output_path(target, relative)
}

fn no_supported_language_response(target: &Path) -> Value {
    let output = format!(
        "cpg:build skipped — no cpg-rs-supported source language detected under {} \
         (supported: {}). Pass `languages=<csv>` to override detection.",
        target.display(),
        kuzushi_cpg::supported_languages().join(", ")
    );
    crate::module_result::skipped_output_result(
        output.clone(),
        output.clone(),
        vec![json!(output)],
        json!({
            "target": target.display().to_string(),
            "skipped": true,
            "reason": "no supported source language detected",
        }),
    )
}

fn cpg_build_response(
    target: &Path,
    source_root: &Path,
    outcome: &CpgBuildOutcome,
    elapsed_ms: u64,
    timestamp: u64,
) -> Result<Value> {
    let output = graph_outcome_text(target, source_root, outcome, elapsed_ms);
    let data = json!({
        "target": target.display().to_string(),
        "engine": "cpg-rs",
        "graphShapeVersion": kuzushi_cpg::GRAPH_SHAPE_VERSION,
        "artifactDir": kuzushi_cpg::artifact_dir(target).display().to_string(),
        "sourceRoot": source_root.display().to_string(),
        "graphs": outcome.reports.iter().map(report_json).collect::<Vec<_>>(),
        "stopReason": outcome.stop_reason,
        "elapsedMs": elapsed_ms,
        "timestamp": timestamp,
    });
    if let Some(reason) = &outcome.stop_reason {
        return Ok(crate::module_result::partial_output_result(
            output.clone(),
            output,
            vec![json!(reason)],
            data,
        ));
    }
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        data,
    ))
}

fn graph_outcome_text(
    target: &Path,
    source_root: &Path,
    outcome: &CpgBuildOutcome,
    elapsed_ms: u64,
) -> String {
    let scope = source_root.strip_prefix(target).unwrap_or(source_root);
    let scope = if scope.as_os_str().is_empty() {
        ".".into()
    } else {
        scope.display().to_string()
    };
    let status = if outcome.stop_reason.is_some() {
        "partial"
    } else {
        "saved"
    };
    let mut lines = vec![
        format!(
            "cpg:build {status} · {} graph(s) saved in {elapsed_ms} ms",
            outcome.reports.len()
        ),
        format!("Source scope: {scope}"),
    ];
    append_graph_locations(&mut lines, target, &outcome.reports);
    lines.push("Auxiliary Map evidence; context requires review and acceptance.".into());
    lines.push(
        "Inspection: source reads and enumeration are not bounded by the build file cap.".into(),
    );
    if let Some(reason) = &outcome.stop_reason {
        lines.push(format!("Stopped: {reason}"));
    }
    lines.join("\n")
}

fn append_graph_locations(
    lines: &mut Vec<String>,
    target: &Path,
    reports: &[kuzushi_cpg::CpgBuildReport],
) {
    for report in reports {
        lines.push(language_report_label(report));
        let path = report
            .cpg_path
            .strip_prefix(target)
            .unwrap_or(&report.cpg_path);
        lines.push(format!("Graph: {}", path.display()));
    }
}

fn report_json(report: &kuzushi_cpg::CpgBuildReport) -> Value {
    json!({
        "language": report.language,
        "cpgPath": report.cpg_path.display().to_string(),
        "reusedCache": report.reused_cache,
        "sourceFiles": report.source_files,
        "methods": report.methods,
        "calls": report.calls,
        "nodes": report.nodes,
        "elapsedMs": report.duration_ms as u64,
    })
}

fn cpg_import_response(
    target: &Path,
    output_path: &Path,
    import_path: &Path,
    lang: &str,
    bytes: u64,
    elapsed_ms: u64,
    timestamp: u64,
) -> Value {
    let output = format!(
        "cpg:build imported {} bytes ({} graph) from {} to {} in {} ms\n\
         Source applicability: not assessed against this checkout.\n\
         Auxiliary Map evidence; context requires review and acceptance.",
        bytes,
        lang,
        import_path.display(),
        output_path.display(),
        elapsed_ms
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "engine": "cpg-rs",
            "language": lang,
            "cpgPath": output_path.display().to_string(),
            "importedFrom": import_path.display().to_string(),
            "currentCheckoutApplicability": "not_assessed",
            "bytes": bytes,
            "elapsedMs": elapsed_ms,
            "timestamp": timestamp,
        }),
    )
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis() as u64)
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, label: impl Into<String>) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, label.into()).emit();
    }
}

#[cfg(test)]
mod cpg_build_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn language_csv_parses_aliases_and_rejects_unknown() {
        assert_eq!(
            parse_language_csv("go, ts,js").unwrap(),
            vec!["go", "typescript", "javascript"]
        );
        assert_eq!(parse_language_csv("go,go").unwrap(), vec!["go"]);
        let error = parse_language_csv("kotlin").unwrap_err().to_string();
        assert!(
            error.contains("does not support language `kotlin`"),
            "{error}"
        );
    }

    #[test]
    fn explicit_languages_beat_detection() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("main.go"), "package main\n").unwrap();
        let detected = resolve_build_languages(&json!({}), temp.path()).unwrap();
        assert_eq!(detected, vec!["go"]);
        let explicit =
            resolve_build_languages(&json!({"languages": "python"}), temp.path()).unwrap();
        assert_eq!(explicit, vec!["python"]);
    }

    #[test]
    fn import_language_requires_convention_and_current_shape() {
        let version = kuzushi_cpg::GRAPH_SHAPE_VERSION;
        assert_eq!(
            import_language(Path::new(&format!("/x/go.v{version}.cpg"))).unwrap(),
            "go"
        );
        // Engine workspace-cache naming (`<key>.<lang>.v<N>.cpg`) parses too.
        assert_eq!(
            import_language(Path::new(&format!(
                "/x/home_repo_src.python.v{version}.cpg"
            )))
            .unwrap(),
            "python"
        );
        assert!(import_language(Path::new("/x/graph.cpg")).is_err());
        assert!(
            import_language(Path::new("/x/go.v1.cpg")).is_err(),
            "stale shape"
        );
        assert!(import_language(Path::new("/x/kotlin.v11.cpg")).is_err());
    }

    #[test]
    fn import_source_must_exist_and_decode() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("absent.cpg");
        assert!(open_cpg_import_source(&missing).is_err());

        let empty = temp.path().join("empty.cpg");
        std::fs::write(&empty, b"").unwrap();
        assert!(open_cpg_import_source(&empty).is_err());

        let truncated = temp.path().join("truncated.cpg");
        std::fs::write(&truncated, b"CPG").unwrap();
        assert!(open_cpg_import_source(&truncated).is_err());

        let wrong = temp.path().join("wrong.cpg");
        std::fs::write(&wrong, b"CPG\0payload").unwrap();
        assert!(open_cpg_import_source(&wrong).is_err());
    }

    #[test]
    fn import_validation_accepts_an_engine_produced_graph() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(
            target.path().join("main.go"),
            "package main\nfunc main() {}\n",
        )
        .unwrap();
        let scope = kuzushi_cpg::BuildScope::whole(target.path());
        let (_, report) =
            kuzushi_cpg::ensure_project_in(&scope, "go", &kuzushi_cpg::BuildLimits::default())
                .unwrap();

        let expected = std::fs::metadata(&report.cpg_path).unwrap().len();
        let source = open_cpg_import_source(&report.cpg_path).unwrap();
        assert_eq!(source.bytes, expected);
        let output = target.path().join("imported.cpg");
        assert_eq!(install_cpg_import(source, &output).unwrap(), expected);
        kuzushi_cpg::validate_graph_artifact(&output).unwrap();
    }

    #[test]
    fn malformed_graph_is_not_published_after_staging() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("go.v11.cpg");
        let output = temp.path().join("canonical.cpg");
        std::fs::write(&source_path, b"CPG2payload").unwrap();

        let source = CpgImportSource {
            file: fs::File::open(&source_path).unwrap(),
            bytes: std::fs::metadata(&source_path).unwrap().len(),
        };
        assert!(install_cpg_import(source, &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn import_source_rejects_directory() {
        let temp = tempfile::tempdir().unwrap();
        assert!(open_cpg_import_source(temp.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cpg_artifact_rejects_preexisting_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::create_dir_all(workspace.path().join(".kuzushi/cpg-rs")).unwrap();
        symlink(
            outside.path(),
            kuzushi_cpg::artifact_path(workspace.path(), "go"),
        )
        .unwrap();

        assert!(prepare_cpg_artifact_path(
            workspace.path(),
            &kuzushi_cpg::artifact_path(workspace.path(), "go")
        )
        .is_err());
    }

    #[test]
    fn subdir_scope_resolves_and_rejects_traversal() {
        let target = Path::new("/repo");
        let scoped = resolve_cpg_scope(&json!({"subdir": "src/go"}), target).unwrap();
        assert_eq!(scoped.scan_root(), PathBuf::from("/repo/src/go"));
        assert!(scoped
            .artifact_path("go")
            .starts_with("/repo/.kuzushi/cpg-rs/scoped"));
        assert!(resolve_cpg_scope(&json!({"subdir": "../out"}), target).is_err());
        let whole = resolve_cpg_scope(&json!({}), target).unwrap();
        assert_eq!(whole.scan_root(), PathBuf::from("/repo"));
    }

    #[test]
    fn max_source_files_parses_and_rejects_nonpositive() {
        assert_eq!(
            resolve_cpg_limits(&json!({})).unwrap().max_source_files,
            kuzushi_cpg::DEFAULT_MAX_SOURCE_FILES
        );
        assert_eq!(
            resolve_cpg_limits(&json!({"maxSourceFiles": 500}))
                .unwrap()
                .max_source_files,
            500
        );
        assert_eq!(
            resolve_cpg_limits(&json!({"max_source_files": "1200"}))
                .unwrap()
                .max_source_files,
            1200
        );
        assert!(resolve_cpg_limits(&json!({"maxSourceFiles": 0})).is_err());
    }

    #[test]
    fn no_supported_language_is_a_graceful_skip() {
        let skip = no_supported_language_response(Path::new("/tmp/t"));
        assert_eq!(skip["status"], "skipped");
        assert_eq!(skip["data"]["skipped"], true);
    }
}
