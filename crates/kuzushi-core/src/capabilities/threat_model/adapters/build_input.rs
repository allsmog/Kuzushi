use super::*;

pub(crate) fn parse_build_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<BuildInput> {
    let mut build = parse_generation_build_input(input)?;
    apply_target_build_input(&mut build, input, ctx, flavor)?;
    Ok(build)
}

/// Generation knobs that need only the raw input value.
fn parse_generation_build_input(input: &Value) -> Result<BuildInput> {
    Ok(BuildInput {
        slice: read_slice(input),
        context_limit: context_limit(input),
        max_source_bytes: max_source_bytes(input),
        max_elements: read_usize(input, &["maxElements", "max_elements"], 40, 5),
        max_threats: read_usize(input, &["maxThreats", "max_threats"], 30, 1),
        max_output_tokens: read_max_output_tokens(input),
        emit_findings: read_bool(input, &["emitFindings", "emit_findings"], false),
        preserve_user_edits: read_bool(input, &["preserveUserEdits", "preserve_user_edits"], true),
        pipeline: read_pipeline(input)?,
        mode: read_build_mode(input)?,
        seed_mode: read_seed_mode(input)?,
        budget_usd: read_budget_usd(input)?,
        history_depth: read_usize(input, &["historyDepth", "history_depth"], 300, 0),
        variant_scan: read_bool(input, &["variantScan", "variant_scan"], true),
        advisories: read_advisories(input)?,
        offline: read_bool(input, &["offline"], false),
        advisory_fixtures: input
            .get("advisoryFixtures")
            .or_else(|| input.get("advisory_fixtures"))
            .cloned(),
        ..Default::default()
    })
}

/// Fields that depend on the resolved target, flavor, or execution context.
fn apply_target_build_input(
    build: &mut BuildInput,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<()> {
    let target = resolve_target(input, ctx)?;
    let context_mode = read_context_mode(input);
    let run_id = Uuid::new_v4().to_string();
    build.output_dir = read_string(input, &["outputDir", "output_dir"])
        .unwrap_or_else(|| flavor.default_output_dir(&target, &run_id));
    build.repo_name = repo_name(&target);
    build.methodology = read_methodology(input, flavor.default_methodology());
    build.sources = read_source_artifacts(input, flavor, &context_mode)?;
    build.seeds = read_string_list(input, &["seed"]);
    build.design_doc = read_string(input, &["designDoc", "design_doc", "design"]);
    build.stages = read_stages(input, flavor.tool_name(), &build.methodology)?;
    build.prompt_override = Some(
        prompt_override(input, &target)?
            .unwrap_or_else(|| DEFAULT_THREAT_MODEL_GUIDANCE.to_string()),
    );
    build.model = build_model(input, ctx, flavor)?;
    build.vulns = read_operator_vulns(input, &target)?;
    build.context_mode = context_mode;
    build.target = target;
    Ok(())
}

const MAX_VULNS_FILE_BYTES: usize = 512 * 1024;

/// Operator-supplied known-vulnerability intake (`vulnsFile`): newline CVE-id
/// list, CSV (`id,title,component,description`), or a JSON array of ids /
/// objects. Read at this adapter boundary so the pipelines receive parsed
/// rows, never a path.
fn read_operator_vulns(input: &Value, target: &Path) -> Result<Vec<OperatorVulnRow>> {
    let Some(path) = read_string(input, &["vulnsFile", "vulns_file", "vulns"]) else {
        return Ok(Vec::new());
    };
    let resolved = if Path::new(&path).is_absolute() {
        PathBuf::from(&path)
    } else {
        target.join(&path)
    };
    let text = crate::bounded_file::read_utf8_text(&resolved, MAX_VULNS_FILE_BYTES)
        .with_context(|| format!("threat-model:build vulnsFile {path} could not be read"))?;
    let rows = parse_vulns_text(&text)?;
    anyhow::ensure!(
        !rows.is_empty(),
        "threat-model:build vulnsFile {path} contained no vulnerability rows"
    );
    Ok(rows)
}

fn parse_vulns_text(text: &str) -> Result<Vec<OperatorVulnRow>> {
    if text.trim_start().starts_with('[') {
        return parse_vulns_json(text);
    }
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    if lines.iter().any(|line| line.contains(',')) {
        return Ok(parse_vulns_csv(&lines));
    }
    Ok(lines
        .iter()
        .map(|id| OperatorVulnRow {
            id: id.to_string(),
            ..Default::default()
        })
        .collect())
}

fn parse_vulns_json(text: &str) -> Result<Vec<OperatorVulnRow>> {
    let rows: Vec<Value> =
        serde_json::from_str(text).context("threat-model:build vulnsFile JSON must be an array")?;
    rows.iter()
        .map(|row| match row {
            Value::String(id) => Ok(OperatorVulnRow {
                id: id.clone(),
                ..Default::default()
            }),
            Value::Object(fields) => json_vuln_row(fields),
            other => anyhow::bail!(
                "threat-model:build vulnsFile JSON rows must be strings or objects, got {other}"
            ),
        })
        .collect()
}

fn json_vuln_row(fields: &Map<String, Value>) -> Result<OperatorVulnRow> {
    let get = |keys: &[&str]| -> String {
        keys.iter()
            .find_map(|key| fields.get(*key).and_then(Value::as_str))
            .unwrap_or("")
            .to_string()
    };
    let id = get(&["id", "cve", "advisory"]);
    anyhow::ensure!(
        !id.is_empty(),
        "threat-model:build vulnsFile JSON object rows require an id"
    );
    Ok(OperatorVulnRow {
        id,
        title: get(&["title", "summary"]),
        component: get(&["component", "package", "module"]),
        description: get(&["description", "details"]),
    })
}

/// Simple comma CSV: `id,title,component,description`; the description keeps
/// embedded commas. A header row whose first field is `id` is skipped.
fn parse_vulns_csv(lines: &[&str]) -> Vec<OperatorVulnRow> {
    lines
        .iter()
        .filter(|line| line.split(',').next().map(str::trim) != Some("id"))
        .map(|line| {
            let mut fields = line.splitn(4, ',').map(str::trim);
            OperatorVulnRow {
                id: fields.next().unwrap_or("").to_string(),
                title: fields.next().unwrap_or("").to_string(),
                component: fields.next().unwrap_or("").to_string(),
                description: fields.next().unwrap_or("").to_string(),
            }
        })
        .filter(|row| !row.id.is_empty())
        .collect()
}

fn read_max_output_tokens(input: &Value) -> u32 {
    read_usize(
        input,
        &["maxOutputTokens", "max_output_tokens"],
        32_000,
        1_024,
    )
    .min(u32::MAX as usize) as u32
}

fn read_pipeline(input: &Value) -> Result<String> {
    let Some(pipeline) = read_string(input, &["pipeline"]) else {
        return Ok("single".to_string());
    };
    let pipeline = pipeline.to_lowercase();
    if !VALID_PIPELINES.contains(&pipeline.as_str()) {
        anyhow::bail!(
            "threat-model:build pipeline must be one of {}, got {pipeline:?}",
            VALID_PIPELINES.join(", ")
        );
    }
    Ok(pipeline)
}

fn read_build_mode(input: &Value) -> Result<String> {
    let Some(mode) = read_string(input, &["mode"]) else {
        return Ok("build".to_string());
    };
    let mode = mode.to_lowercase();
    if !VALID_BUILD_MODES.contains(&mode.as_str()) {
        anyhow::bail!(
            "threat-model:build mode must be one of {}, got {mode:?}",
            VALID_BUILD_MODES.join(", ")
        );
    }
    Ok(mode)
}

fn read_seed_mode(input: &Value) -> Result<String> {
    let Some(seed_mode) = read_string(input, &["seedMode", "seed_mode"]) else {
        return Ok("seeded".to_string());
    };
    let seed_mode = seed_mode.to_lowercase();
    if !VALID_SEED_MODES.contains(&seed_mode.as_str()) {
        anyhow::bail!(
            "threat-model:build seedMode must be one of {}, got {seed_mode:?}",
            VALID_SEED_MODES.join(", ")
        );
    }
    Ok(seed_mode)
}

fn read_advisories(input: &Value) -> Result<String> {
    let Some(advisories) = read_string(input, &["advisories"]) else {
        return Ok("off".to_string());
    };
    let advisories = advisories.to_lowercase();
    if !VALID_ADVISORY_MODES.contains(&advisories.as_str()) {
        anyhow::bail!(
            "threat-model:build advisories must be one of {}, got {advisories:?}",
            VALID_ADVISORY_MODES.join(", ")
        );
    }
    Ok(advisories)
}

fn read_budget_usd(input: &Value) -> Result<Option<f64>> {
    let Some(budget) = input.get("budgetUsd").or_else(|| input.get("budget_usd")) else {
        return Ok(None);
    };
    let budget = budget
        .as_f64()
        .context("threat-model:build budgetUsd must be a number")?;
    anyhow::ensure!(
        budget.is_finite() && budget > 0.0,
        "threat-model:build budgetUsd must be a positive number, got {budget}"
    );
    Ok(Some(budget))
}

fn context_limit(input: &Value) -> usize {
    read_usize(
        input,
        &[
            "contextLimit",
            "contextSampleLimit",
            "context_sample_limit",
            "sampleLimit",
        ],
        200,
        1,
    )
    .min(2_000)
}

fn max_source_bytes(input: &Value) -> usize {
    read_usize(input, &["maxSourceBytes", "max_source_bytes"], 200_000, 1).min(MAX_SOURCE_BYTES)
}

fn prompt_override(input: &Value, target: &Path) -> Result<Option<String>> {
    read_string(input, &["THREAT_MODEL_PROMPT"])
        .map(|value| {
            crate::options::resolve_prepared_prompt_override_for_key(
                &value,
                target,
                "THREAT_MODEL_PROMPT",
                crate::capabilities::threat_model::DEFAULT_THREAT_MODEL_GUIDANCE,
            )
        })
        .transpose()
}

fn build_model(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<String> {
    crate::runtime::resolve_explicit_model(
        flavor.tool_name(),
        read_string(input, &["model"]),
        ctx.config.model.as_deref(),
    )
}

fn read_source_artifacts(
    input: &Value,
    flavor: BuildFlavor,
    context_mode: &str,
) -> Result<Vec<String>> {
    let sources = source_artifact_values(input, flavor);
    let normalized = normalize_source_artifacts(sources)?;
    reject_invalid_source_artifact_combo(&normalized)?;
    Ok(source_artifacts_for_context_mode(normalized, context_mode))
}

fn source_artifact_values(input: &Value, flavor: BuildFlavor) -> Vec<String> {
    let sources = read_string_list(input, &["sources", "sourceArtifacts", "source_artifacts"]);
    if sources.is_empty() {
        return default_source_artifacts(flavor);
    }
    sources
}

fn default_source_artifacts(flavor: BuildFlavor) -> Vec<String> {
    match flavor {
        BuildFlavor::ThreatModel => vec!["context".to_string(), "threat-model".to_string()],
        BuildFlavor::RandoriPasta => vec!["none".to_string()],
    }
}

fn normalize_source_artifacts(sources: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    for source in sources {
        let source = source.to_lowercase();
        validate_source_artifact(&source)?;
        push_unique_source_artifact(&mut normalized, source);
    }
    Ok(normalized)
}

fn validate_source_artifact(source: &str) -> Result<()> {
    if !VALID_SOURCE_ARTIFACTS.contains(&source) {
        anyhow::bail!(
            "threat-model:build sources contains unsupported value {source:?}; use one of {}",
            VALID_SOURCE_ARTIFACTS.join(", ")
        );
    }
    Ok(())
}

fn push_unique_source_artifact(sources: &mut Vec<String>, source: String) {
    if !sources.iter().any(|seen| seen == &source) {
        sources.push(source);
    }
}

fn reject_invalid_source_artifact_combo(sources: &[String]) -> Result<()> {
    if sources.iter().any(|source| source == "none") && sources.len() > 1 {
        anyhow::bail!(
            "threat-model:build sources value \"none\" cannot be combined with other sources"
        );
    }
    Ok(())
}

fn source_artifacts_for_context_mode(sources: Vec<String>, context_mode: &str) -> Vec<String> {
    if context_mode == "off" && source_lists_match(&sources, &["context", "threat-model"]) {
        return vec!["none".to_string()];
    }
    sources
}

fn source_lists_match(actual: &[String], expected: &[&str]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    expected
        .iter()
        .all(|expected| actual.iter().any(|actual| actual == expected))
}

fn read_context_mode(input: &Value) -> String {
    read_string(input, &["contextMode", "context_mode"])
        .map(|value| value.to_lowercase())
        .filter(|value| VALID_CONTEXT_MODES.contains(&value.as_str()))
        .unwrap_or_else(|| "auto".to_string())
}

pub(crate) fn read_string_list(input: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| match input.get(*key) {
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            Some(Value::String(value)) => Some(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod seed_mode_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn seed_mode_defaults_to_seeded_and_accepts_fresh() {
        assert_eq!(read_seed_mode(&json!({})).unwrap(), "seeded");
        assert_eq!(
            read_seed_mode(&json!({"seedMode": "fresh"})).unwrap(),
            "fresh"
        );
        assert_eq!(
            read_seed_mode(&json!({"seed_mode": "SEEDED"})).unwrap(),
            "seeded"
        );
    }

    #[test]
    fn unknown_seed_mode_is_rejected() {
        let error = read_seed_mode(&json!({"seedMode": "recursive"})).unwrap_err();
        assert!(error.to_string().contains("seedMode"));
    }
}

#[cfg(test)]
mod vulns_file_tests {
    use super::*;

    #[test]
    fn newline_cve_list_parses_to_id_only_rows() {
        let rows = parse_vulns_text("# known vulns\nCVE-2026-1234\n\nCVE-2025-9\n").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "CVE-2026-1234");
        assert!(rows[0].title.is_empty());
    }

    #[test]
    fn csv_rows_parse_and_header_is_skipped() {
        let text = "id,title,component,description\n\
                    CVE-2026-1,heap overflow,decoder,write past end, with commas\n";
        let rows = parse_vulns_text(text).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "CVE-2026-1");
        assert_eq!(rows[0].title, "heap overflow");
        assert_eq!(rows[0].component, "decoder");
        assert_eq!(rows[0].description, "write past end, with commas");
    }

    #[test]
    fn json_array_accepts_strings_and_objects() {
        let text = r#"[
            "CVE-2026-2",
            {"id": "GHSA-x", "summary": "ssrf", "package": "reqlib", "description": "long form"}
        ]"#;
        let rows = parse_vulns_text(text).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "CVE-2026-2");
        assert_eq!(rows[1].id, "GHSA-x");
        assert_eq!(rows[1].title, "ssrf");
        assert_eq!(rows[1].component, "reqlib");
    }

    #[test]
    fn json_object_row_without_id_is_rejected() {
        assert!(parse_vulns_text(r#"[{"summary": "no id"}]"#).is_err());
    }
}
