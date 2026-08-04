use super::*;

const X_RAY_DIR: &str = "x-ray";
const X_RAY_MD: &str = "x-ray.md";
const X_RAY_ENTRY_POINTS_MD: &str = "entry-points.md";
const X_RAY_INVARIANTS_MD: &str = "invariants.md";

#[derive(Debug, Clone)]
pub(crate) struct ThreatModelSourceBundle {
    records: Vec<ThreatModelSourceRecord>,
}

impl ThreatModelSourceBundle {
    pub(crate) fn metadata_json(&self) -> Value {
        Value::Array(
            self.records
                .iter()
                .map(ThreatModelSourceRecord::metadata_json)
                .collect(),
        )
    }

    pub(crate) fn prompt_blocks(&self) -> String {
        let blocks = self
            .records
            .iter()
            .filter_map(ThreatModelSourceRecord::prompt_block)
            .collect::<Vec<_>>();
        if blocks.is_empty() {
            "No loaded parent artifacts. Use repository inventory and manifest evidence only."
                .to_string()
        } else {
            blocks.join("\n\n")
        }
    }

    pub(crate) fn loaded_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.content.is_some())
            .count()
    }

    /// System-attested provenance rows for the persisted document: what the
    /// build actually consumed, recorded by the loader rather than claimed by
    /// the model. Skipped records are kept — a source that was *not* in the
    /// prompt is provenance too. Local paths and byte counts are omitted
    /// because the document travels beyond this machine.
    pub(crate) fn provenance_json(&self) -> Value {
        Value::Array(
            self.records
                .iter()
                .map(ThreatModelSourceRecord::provenance_json)
                .collect(),
        )
    }

    pub(crate) fn authenticate_entry_point_sources(
        &self,
        receipt: &crate::capabilities::entry_points::EntryPointCatalogReceipt,
    ) -> Result<()> {
        if let Some(expected) = receipt.context_sha256.as_deref() {
            self.authenticate_loaded_source("context", expected, false)?;
        }
        if receipt.sha256.is_some() {
            let expected = catalog_pair_digest_from_receipt(receipt)?;
            self.authenticate_loaded_source("entry-points", &expected, true)?;
        }
        Ok(())
    }

    fn authenticate_loaded_source(
        &self,
        label: &str,
        expected: &str,
        payload: bool,
    ) -> Result<()> {
        let Some(record) = self.records.iter().find(|record| record.label == label) else {
            return Ok(());
        };
        let actual = if payload {
            record.catalog_pair_sha256.as_deref()
        } else {
            record.sha256.as_deref()
        };
        anyhow::ensure!(
            actual == Some(expected),
            "{label} source changed between source loading and entry-point grounding"
        );
        Ok(())
    }
}

fn catalog_pair_digest_from_receipt(
    receipt: &crate::capabilities::entry_points::EntryPointCatalogReceipt,
) -> Result<String> {
    let payload = receipt
        .sha256
        .as_deref()
        .context("entry-point catalog receipt has no payload digest")?;
    let context = receipt
        .context_sha256
        .as_deref()
        .context("entry-point catalog receipt has no context digest")?;
    let timestamp = receipt
        .snapshot_timestamp
        .context("entry-point catalog receipt has no snapshot timestamp")?;
    Ok(catalog_pair_digest(
        payload,
        context,
        timestamp,
        receipt.tree_hash.as_deref(),
    ))
}

fn catalog_pair_digest(
    payload: &str,
    context: &str,
    timestamp: u64,
    tree_hash: Option<&str>,
) -> String {
    let material = format!(
        "{payload}\0{context}\0{timestamp}\0{}",
        tree_hash.unwrap_or("none")
    );
    crate::options::prompt_content_sha256(&material)
}

#[derive(Debug, Clone)]
struct ThreatModelSourceRecord {
    kind: String,
    label: String,
    path: Option<PathBuf>,
    status: String,
    note: Option<String>,
    sha256: Option<String>,
    catalog_pair_sha256: Option<String>,
    bytes: usize,
    truncated: bool,
    content: Option<String>,
}

impl ThreatModelSourceRecord {
    fn loaded(
        kind: &str,
        label: &str,
        path: Option<PathBuf>,
        content: String,
        limit: usize,
    ) -> Self {
        let bytes = content.len();
        let sha256 = Some(crate::options::prompt_content_sha256(&content));
        let (content, truncated) = truncate_source_content(content, limit);
        Self {
            kind: kind.to_string(),
            label: label.to_string(),
            path,
            status: "loaded".to_string(),
            note: None,
            sha256,
            catalog_pair_sha256: None,
            bytes,
            truncated,
            content: Some(content),
        }
    }

    fn skipped(kind: &str, label: &str, path: PathBuf, note: &str) -> Self {
        Self {
            kind: kind.to_string(),
            label: label.to_string(),
            path: Some(path),
            status: "skipped".to_string(),
            note: Some(note.to_string()),
            sha256: None,
            catalog_pair_sha256: None,
            bytes: 0,
            truncated: false,
            content: None,
        }
    }

    fn projected(
        label: &str,
        path: PathBuf,
        original: &str,
        catalog_pair_sha256: String,
        content: String,
        truncated: bool,
    ) -> Self {
        Self {
            kind: "artifact".to_string(),
            label: label.to_string(),
            path: Some(path),
            status: "loaded".to_string(),
            note: None,
            sha256: Some(crate::options::prompt_content_sha256(original)),
            catalog_pair_sha256: Some(catalog_pair_sha256),
            bytes: original.len(),
            truncated,
            content: Some(content),
        }
    }

    fn metadata_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "label": self.label,
            "path": self.path.as_ref().map(|path| path.display().to_string()),
            "status": self.status,
            "note": self.note,
            "sha256": self.sha256,
            "catalogPairSha256": self.catalog_pair_sha256,
            "bytes": self.bytes,
            "truncated": self.truncated,
        })
    }

    fn provenance_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "label": self.label,
            "status": self.status,
            "sha256": self.sha256,
            "catalogPairSha256": self.catalog_pair_sha256,
            "truncated": self.truncated,
        })
    }

    fn prompt_block(&self) -> Option<String> {
        let content = self.content.as_ref()?;
        let path = self
            .path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "inline".to_string());
        Some(format!(
            r#"<untrusted-source label="{label}" kind="{kind}" path="{path}" sha256="{sha256}" truncated="{truncated}">
{content}
</untrusted-source>"#,
            label = self.label,
            kind = self.kind,
            path = path,
            sha256 = self.sha256.as_deref().unwrap_or("none"),
            truncated = self.truncated,
            content = content,
        ))
    }
}

pub(crate) fn load_threat_model_source_bundle(
    ctx: &ToolExecutionContext<'_>,
    input: &BuildInput,
) -> Result<ThreatModelSourceBundle> {
    reject_conflicting_context_source(input)?;
    let mut records = Vec::new();
    if parent_artifacts_enabled(input) {
        load_parent_artifacts(ctx, input, &mut records)?;
    }
    load_operator_sources(ctx, input, &mut records)?;
    Ok(ThreatModelSourceBundle { records })
}

fn parent_artifacts_enabled(input: &BuildInput) -> bool {
    !input.sources.iter().any(|source| source == "none")
}

fn reject_conflicting_context_source(input: &BuildInput) -> Result<()> {
    if input.context_mode == "off" && input.sources.iter().any(|source| source == "context") {
        anyhow::bail!(
            "threat-model:build contextMode=off conflicts with sources containing \"context\""
        );
    }
    Ok(())
}

fn load_parent_artifacts(
    ctx: &ToolExecutionContext<'_>,
    input: &BuildInput,
    records: &mut Vec<ThreatModelSourceRecord>,
) -> Result<()> {
    for source in &input.sources {
        match source.as_str() {
            "context" => records.push(load_context_source(ctx, input)?),
            "threat-model" => records.push(prior_threat_model_source(input)?),
            "x-ray" => records.push(load_x_ray_source(input)?),
            "entry-points" => records.push(load_entry_points_source(input)?),
            "none" => {}
            _ => anyhow::bail!("unsupported threat-model source {source:?}"),
        }
    }
    Ok(())
}

fn load_operator_sources(
    ctx: &ToolExecutionContext<'_>,
    input: &BuildInput,
    records: &mut Vec<ThreatModelSourceRecord>,
) -> Result<()> {
    if let Some(design_doc) = input.design_doc.as_deref() {
        records.push(load_design_doc_source(input, design_doc)?);
        emit_source_step(ctx, "source:operator design doc");
    }
    for (index, seed) in input.seeds.iter().enumerate() {
        records.push(load_seed_source(input, index + 1, seed)?);
    }
    if !input.seeds.is_empty() {
        emit_source_step(ctx, "source:operator seed");
    }
    Ok(())
}

fn load_context_source(
    ctx: &ToolExecutionContext<'_>,
    input: &BuildInput,
) -> Result<ThreatModelSourceRecord> {
    let path = crate::context::context_snapshot_path(&input.target);
    let content = match input.context_mode.as_str() {
        "refresh" => {
            emit_source_step(ctx, "source:context refresh");
            build_context_source_content(input)?
        }
        "require" => {
            emit_source_step(ctx, "source:context require");
            read_context_json_source(&input.target, &path)?
        }
        _ if path.exists() => {
            emit_source_step(ctx, "source:context load");
            read_context_json_source(&input.target, &path)?
        }
        _ => {
            emit_source_step(ctx, "source:context build");
            build_context_source_content(input)?
        }
    };
    Ok(ThreatModelSourceRecord::loaded(
        "artifact",
        "context",
        Some(path),
        content,
        input.max_source_bytes,
    ))
}

fn build_context_source_content(input: &BuildInput) -> Result<String> {
    crate::modules::context::build_context_snapshot_for_root(
        &input.target,
        input.context_limit,
    )
    .with_context(|| "Could not build context snapshot for threat-model:build")?;
    let path = crate::context::context_snapshot_path(&input.target);
    read_context_json_source(&input.target, &path)
}

/// The prior model is the one source whose loading is a *lineage* decision,
/// not an evidence decision. `sources` records what the caller asked for;
/// `embeds_prior_model()` decides whether it reaches the prompt, so a fresh
/// build attests the exclusion instead of silently dropping the row.
fn prior_threat_model_source(input: &BuildInput) -> Result<ThreatModelSourceRecord> {
    if !input.embeds_prior_model() {
        return Ok(ThreatModelSourceRecord::skipped(
            "artifact",
            "threat-model",
            persistent_threat_model_path(&input.target),
            "seedMode=fresh: persisted model excluded from the prompt",
        ));
    }
    load_prior_threat_model_source(input)
}

fn load_prior_threat_model_source(input: &BuildInput) -> Result<ThreatModelSourceRecord> {
    let path = persistent_threat_model_path(&input.target);
    if !path.exists() {
        return Ok(ThreatModelSourceRecord::skipped(
            "artifact",
            "threat-model",
            path,
            "no prior persistent threat model",
        ));
    }
    let content = read_json_source(&input.target, &path, "prior threat model")?;
    Ok(ThreatModelSourceRecord::loaded(
        "artifact",
        "threat-model",
        Some(path),
        content,
        input.max_source_bytes,
    ))
}

fn load_x_ray_source(input: &BuildInput) -> Result<ThreatModelSourceRecord> {
    let dir = input.target.join(X_RAY_DIR);
    let x_ray = read_required_text(&input.target, &dir.join(X_RAY_MD), "x-ray source")?;
    let entry_points = read_required_text(
        &input.target,
        &dir.join(X_RAY_ENTRY_POINTS_MD),
        "x-ray entry points",
    )?;
    let invariants = read_required_text(
        &input.target,
        &dir.join(X_RAY_INVARIANTS_MD),
        "x-ray invariants",
    )?;
    let content = format!(
        "# x-ray.md\n{x_ray}\n\n# entry-points.md\n{entry_points}\n\n# invariants.md\n{invariants}"
    );
    Ok(ThreatModelSourceRecord::loaded(
        "artifact",
        "x-ray",
        Some(dir),
        content,
        input.max_source_bytes,
    ))
}

fn load_entry_points_source(input: &BuildInput) -> Result<ThreatModelSourceRecord> {
    let resolution = entry_points_source_catalog(input)?;
    let path = resolution.path;
    let catalog = resolution
        .catalog
        .context("entry-points source resolution returned no catalog")?;
    // Project the exact typed value that passed catalog authentication. A
    // second path read here would reopen a TOCTOU window between validation
    // and prompt construction.
    let catalog_pair_sha256 = catalog_pair_digest(
        &catalog.provenance.sha256,
        &catalog.provenance.context_snapshot_sha256,
        catalog.snapshot_timestamp,
        catalog.provenance.context_snapshot_tree_hash.as_deref(),
    );
    let original = serde_json::to_string(&catalog)?;
    let document = serde_json::to_value(catalog)?;
    let (content, truncated) = project_entry_points_source(&document, input.max_source_bytes)?;
    Ok(ThreatModelSourceRecord::projected(
        "entry-points",
        path,
        &original,
        catalog_pair_sha256,
        content,
        truncated,
    ))
}

fn entry_points_source_catalog(
    input: &BuildInput,
) -> Result<crate::capabilities::entry_points::EntryPointCatalogResolution> {
    if input.context_mode == "off" {
        crate::capabilities::entry_points::load_explicit_entry_point_catalog(&input.target)
    } else {
        let resolution =
            crate::capabilities::entry_points::ensure_current_entry_point_catalog(&input.target)?;
        if resolution.catalog.is_none() {
            crate::capabilities::entry_points::load_explicit_entry_point_catalog(&input.target)
        } else {
            Ok(resolution)
        }
    }
}

fn project_entry_points_source(document: &Value, limit: usize) -> Result<(String, bool)> {
    let rows = document
        .get("entryPoints")
        .and_then(Value::as_array)
        .context("entry-points artifact has no entryPoints array")?;
    let serialized_rows = rows
        .iter()
        .map(serde_json::to_string)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let baseline = entry_points_projection(document, &[], rows.len())?;
    anyhow::ensure!(
        baseline.len() <= limit,
        "maxSourceBytes={limit} is too small for a row-safe entry-points projection"
    );
    let mut selected = 0;
    let mut row_bytes = 0;
    for row in &serialized_rows {
        let next_bytes = row_bytes + row.len() + usize::from(selected > 0);
        if projection_size(document, rows.len(), selected + 1, next_bytes)? > limit {
            break;
        }
        selected += 1;
        row_bytes = next_bytes;
    }
    let content = entry_points_projection(document, &serialized_rows[..selected], rows.len())?;
    Ok((content, selected < rows.len()))
}

fn projection_size(
    document: &Value,
    total: usize,
    selected: usize,
    row_bytes: usize,
) -> Result<usize> {
    Ok(entry_points_projection_prefix(document, total, selected)?.len() + row_bytes + 2)
}

fn entry_points_projection(document: &Value, rows: &[String], total: usize) -> Result<String> {
    let mut content = entry_points_projection_prefix(document, total, rows.len())?;
    content.push_str(&rows.join(","));
    content.push_str("]}");
    Ok(content)
}

fn entry_points_projection_prefix(
    document: &Value,
    total: usize,
    selected: usize,
) -> Result<String> {
    let value = json!({
        "target": document.get("target"),
        "snapshotTimestamp": document.get("snapshotTimestamp"),
        "total": document.get("total").and_then(Value::as_u64).map_or(total as u64, |value| value),
        "recordsSelected": selected,
        "provenance": document.get("provenance"),
    });
    let mut prefix =
        serde_json::to_string(&value).context("serializing row-safe entry-points projection")?;
    prefix.pop();
    prefix.push_str(",\"entryPoints\":[");
    Ok(prefix)
}

fn load_design_doc_source(input: &BuildInput, design_doc: &str) -> Result<ThreatModelSourceRecord> {
    let path = resolve_source_path(&input.target, design_doc);
    let content = read_required_text(&input.target, &path, "designDoc")?;
    Ok(ThreatModelSourceRecord::loaded(
        "operator",
        "designDoc",
        Some(path),
        content,
        input.max_source_bytes,
    ))
}

fn load_seed_source(
    input: &BuildInput,
    index: usize,
    seed: &str,
) -> Result<ThreatModelSourceRecord> {
    let label = format!("seed-{index}");
    let path = resolve_source_path(&input.target, seed);
    if looks_like_source_path(seed) || path.exists() {
        let content = read_required_text(&input.target, &path, "seed")?;
        return Ok(ThreatModelSourceRecord::loaded(
            "operator",
            &label,
            Some(path),
            content,
            input.max_source_bytes,
        ));
    }
    Ok(ThreatModelSourceRecord::loaded(
        "operator",
        &label,
        None,
        seed.to_string(),
        input.max_source_bytes,
    ))
}

fn read_json_source(root: &Path, path: &Path, label: &str) -> Result<String> {
    read_json_source_with_limit(root, path, label, MAX_SOURCE_BYTES)
}

fn read_context_json_source(root: &Path, path: &Path) -> Result<String> {
    read_json_source_with_limit(
        root,
        path,
        "context snapshot",
        crate::context::MAX_CONTEXT_SNAPSHOT_BYTES,
    )
}

fn read_json_source_with_limit(
    root: &Path,
    path: &Path,
    label: &str,
    max_bytes: usize,
) -> Result<String> {
    let raw = read_required_text_with_limit(root, path, label, max_bytes)?;
    serde_json::from_str::<serde::de::IgnoredAny>(&raw)
        .with_context(|| format!("{label} at {} is not valid JSON", path.display()))?;
    Ok(raw)
}

fn read_required_text(root: &Path, path: &Path, label: &str) -> Result<String> {
    read_required_text_with_limit(root, path, label, MAX_SOURCE_BYTES)
}

fn read_required_text_with_limit(
    root: &Path,
    path: &Path,
    label: &str,
    max_bytes: usize,
) -> Result<String> {
    crate::bounded_file::read_utf8_text_within(root, path, max_bytes)
        .with_context(|| format!("Could not read {label} from {}", path.display()))
}

fn resolve_source_path(root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value.trim());
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn looks_like_source_path(value: &str) -> bool {
    let value = value.trim();
    if value.starts_with("./") || value.starts_with("../") || value.starts_with('/') {
        return true;
    }
    if value.chars().any(char::is_whitespace) {
        return false;
    }
    value.ends_with(".md")
        || value.ends_with(".txt")
        || value.ends_with(".prompt")
        || value.ends_with(".json")
        || value.ends_with(".jsonl")
        || value.ends_with(".toml")
        || value.ends_with(".yaml")
        || value.ends_with(".yml")
}

fn truncate_source_content(content: String, limit: usize) -> (String, bool) {
    if content.len() <= limit {
        return (content, false);
    }
    let mut end = limit;
    while end > 0 && !content.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = format!(
        "{}\n[truncated by kuzushi: original_bytes={}]",
        &content[..end],
        content.len()
    );
    (truncated, true)
}

fn emit_source_step(ctx: &ToolExecutionContext<'_>, label: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step("tool-progress", "build", label).emit();
    }
}

#[cfg(test)]
mod source_size_contract_tests {
    use super::*;

    fn paired_source_receipt() -> crate::capabilities::entry_points::EntryPointCatalogReceipt {
        let mut receipt =
            crate::capabilities::entry_points::EntryPointCatalogReceipt::unavailable("current");
        receipt.sha256 = Some("sha256:catalog-payload".to_string());
        receipt.context_sha256 = Some("sha256:context-content".to_string());
        receipt.snapshot_timestamp = Some(9);
        receipt
    }

    #[test]
    fn source_bundle_rejects_a_different_catalog_context_pair() {
        let context = ThreatModelSourceRecord {
            kind: "artifact".to_string(),
            label: "context".to_string(),
            path: None,
            status: "loaded".to_string(),
            note: None,
            sha256: Some("sha256:different-context".to_string()),
            catalog_pair_sha256: None,
            bytes: 2,
            truncated: false,
            content: Some("{}".to_string()),
        };
        let catalog = ThreatModelSourceRecord::projected(
            "entry-points",
            PathBuf::from("entry-points.json"),
            "{}",
            catalog_pair_digest(
                "sha256:catalog-payload",
                "sha256:context-content",
                9,
                None,
            ),
            "{}".to_string(),
            false,
        );
        let bundle = ThreatModelSourceBundle {
            records: vec![context, catalog],
        };

        let error = bundle
            .authenticate_entry_point_sources(&paired_source_receipt())
            .unwrap_err();

        assert!(error.to_string().contains("context source changed"));
    }

    #[test]
    fn source_bundle_rejects_a_different_catalog_payload() {
        let context = ThreatModelSourceRecord::loaded(
            "artifact",
            "context",
            None,
            "context".to_string(),
            100,
        );
        let mut receipt = paired_source_receipt();
        receipt.context_sha256 = context.sha256.clone();
        let catalog = ThreatModelSourceRecord::projected(
            "entry-points",
            PathBuf::from("entry-points.json"),
            "{}",
            catalog_pair_digest("sha256:different", receipt.context_sha256.as_deref().unwrap(), 9, None),
            "{}".to_string(),
            false,
        );
        let bundle = ThreatModelSourceBundle {
            records: vec![context, catalog],
        };

        let error = bundle
            .authenticate_entry_point_sources(&receipt)
            .unwrap_err();

        assert!(error.to_string().contains("entry-points source changed"));
    }

    #[test]
    fn context_snapshot_may_exceed_the_ordinary_prompt_source_read_limit() {
        let target = tempfile::tempdir().unwrap();
        let path = crate::context::context_snapshot_path(target.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let padding = "x".repeat(MAX_SOURCE_BYTES + 1);
        std::fs::write(&path, serde_json::json!({ "padding": padding }).to_string()).unwrap();

        let content = read_context_json_source(target.path(), &path).unwrap();

        assert!(content.len() > MAX_SOURCE_BYTES);
    }

    #[test]
    fn context_snapshot_still_has_a_bounded_artifact_read() {
        let target = tempfile::tempdir().unwrap();
        let path = crate::context::context_snapshot_path(target.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = std::fs::File::create(&path).unwrap();
        file.set_len((crate::context::MAX_CONTEXT_SNAPSHOT_BYTES + 1) as u64)
            .unwrap();

        let error = read_context_json_source(target.path(), &path).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Could not read context snapshot"),
            "{error:#}"
        );
    }

    #[test]
    fn entry_points_projection_keeps_whole_rows_and_valid_json() {
        let row = |id: &str| {
            json!({
                "id": id,
                "kind": "http_route",
                "path": format!("src/{id}.rs"),
                "evidence": "x".repeat(80),
            })
        };
        let document = json!({
            "target": "/repo",
            "snapshotTimestamp": 9,
            "total": 3,
            "provenance": {"sha256": "sha256:payload"},
            "entryPoints": [row("a"), row("b"), row("c")],
        });
        let row_a = serde_json::to_string(&row("a")).unwrap();
        let one_row = entry_points_projection(&document, &[row_a], 3).unwrap();

        let (projected, truncated) = project_entry_points_source(&document, one_row.len()).unwrap();
        let parsed: Value = serde_json::from_str(&projected).unwrap();

        assert!(truncated);
        assert_eq!(parsed["recordsSelected"], json!(1));
        assert_eq!(parsed["entryPoints"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["entryPoints"][0]["id"], json!("a"));
    }

    #[test]
    fn none_disables_parent_sources_without_changing_the_default_contract() {
        let none = BuildInput {
            sources: vec!["none".to_string()],
            ..BuildInput::default()
        };
        let defaults = BuildInput {
            sources: vec!["context".to_string(), "threat-model".to_string()],
            ..BuildInput::default()
        };

        assert!(!parent_artifacts_enabled(&none));
        assert!(parent_artifacts_enabled(&defaults));
        assert!(!defaults
            .sources
            .iter()
            .any(|source| source == "entry-points"));
    }

    #[test]
    fn large_entry_point_projection_remains_valid_and_bounded() {
        let rows = (0..519)
            .map(|index| {
                json!({
                    "id": format!("AS-{index}"),
                    "kind": "http_route",
                    "path": format!("src/routes/{index}.rs"),
                    "evidence": "route declaration",
                })
            })
            .collect::<Vec<_>>();
        let document = json!({
            "target": "/repo",
            "snapshotTimestamp": 9,
            "total": rows.len(),
            "provenance": {"sha256": "sha256:payload"},
            "entryPoints": rows,
        });

        let (projected, truncated) = project_entry_points_source(&document, 12_000).unwrap();
        let parsed: Value = serde_json::from_str(&projected).unwrap();

        assert!(truncated);
        assert!(projected.len() <= 12_000);
        assert_eq!(
            parsed["entryPoints"].as_array().unwrap().len(),
            parsed["recordsSelected"].as_u64().unwrap() as usize
        );
        assert!(parsed["recordsSelected"].as_u64().unwrap() > 100);
    }

    #[test]
    fn context_off_explicit_source_ignores_a_malformed_context_snapshot() {
        let target = tempfile::tempdir().unwrap();
        let state = crate::workspace::workspace_state_root(target.path());
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("context-snapshot.json"), "malformed context").unwrap();
        let mut surface = crate::attack_surface::AttackSurface {
            id: String::new(),
            kind: crate::attack_surface::AttackSurfaceKind::HttpRoute,
            path: "src/one.rs".to_string(),
            line: Some(1),
            language: "Rust".to_string(),
            framework: None,
            title: "GET /one".to_string(),
            evidence: "router.get".to_string(),
            method: Some("GET".to_string()),
            route: Some("/one".to_string()),
            boundary: None,
            risk: crate::attack_surface::AttackSurfaceRisk::default(),
            metadata: Value::Null,
        };
        surface.id = crate::workspace::attack_surface::attack_surface_id(&surface);
        let expected_id = surface.id.clone();
        let entries = vec![crate::capabilities::entry_points::EntryPointRecord {
            name: json!("GET /one"),
            location: json!("src/one.rs:1"),
            surface,
            extra: Map::new(),
        }];
        let catalog = explicit_test_catalog(target.path(), entries);
        std::fs::write(
            state.join("entry-points.json"),
            serde_json::to_vec_pretty(&catalog).unwrap(),
        )
        .unwrap();
        let input = BuildInput {
            target: target.path().to_path_buf(),
            context_mode: "off".to_string(),
            sources: vec!["entry-points".to_string()],
            max_source_bytes: 10_000,
            ..BuildInput::default()
        };

        let record = load_entry_points_source(&input).unwrap();
        let projected: Value = serde_json::from_str(record.content.as_deref().unwrap()).unwrap();

        assert_eq!(projected["entryPoints"][0]["id"], json!(expected_id));
        assert_eq!(record.status, "loaded");
    }

    fn explicit_test_catalog(
        target: &Path,
        entries: Vec<crate::capabilities::entry_points::EntryPointRecord>,
    ) -> crate::capabilities::entry_points::EntryPointCatalog {
        let sha256 = crate::capabilities::entry_points::entry_points_sha256(&entries).unwrap();
        crate::capabilities::entry_points::EntryPointCatalog {
            target: target.canonicalize().unwrap().display().to_string(),
            timestamp: 10,
            snapshot_timestamp: 9,
            total: entries.len(),
            entry_points: entries,
            provenance: crate::capabilities::entry_points::EntryPointCatalogProvenance {
                built_at_ms: 10,
                sha256,
                revision: None,
                revision_dirty: None,
                context_snapshot_timestamp: 9,
                context_snapshot_sha256: "sha256:context".to_string(),
                context_snapshot_tree_hash: Some(
                    crate::incremental_index::current_workspace_tree_hash(target).unwrap(),
                ),
            },
        }
    }
}
