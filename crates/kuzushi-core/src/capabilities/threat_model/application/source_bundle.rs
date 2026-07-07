use super::*;

const X_RAY_DIR: &str = "x-ray";
const X_RAY_MD: &str = "x-ray.md";
const X_RAY_ENTRY_POINTS_MD: &str = "entry-points.md";
const X_RAY_INVARIANTS_MD: &str = "invariants.md";
const ENTRY_POINTS_FILE: &str = "entry-points.json";

#[derive(Debug, Clone)]
pub(crate) struct ThreatModelSourceBundle {
    records: Vec<ThreatModelSourceRecord>,
}

impl ThreatModelSourceBundle {
    pub(crate) fn metadata_json(&self) -> Value {
        Value::Array(self.records.iter().map(ThreatModelSourceRecord::metadata_json).collect())
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
}

#[derive(Debug, Clone)]
struct ThreatModelSourceRecord {
    kind: String,
    label: String,
    path: Option<PathBuf>,
    status: String,
    note: Option<String>,
    sha256: Option<String>,
    bytes: usize,
    truncated: bool,
    content: Option<String>,
}

impl ThreatModelSourceRecord {
    fn loaded(kind: &str, label: &str, path: Option<PathBuf>, content: String, limit: usize) -> Self {
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
            bytes: 0,
            truncated: false,
            content: None,
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
            "bytes": self.bytes,
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
    if !input.sources.iter().any(|source| source == "none") {
        load_parent_artifacts(ctx, input, &mut records)?;
    }
    load_operator_sources(ctx, input, &mut records)?;
    Ok(ThreatModelSourceBundle { records })
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
            "threat-model" => records.push(load_prior_threat_model_source(input)?),
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
            read_json_source(&path, "context snapshot")?
        }
        _ if path.exists() => {
            emit_source_step(ctx, "source:context load");
            read_json_source(&path, "context snapshot")?
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
    let built =
        crate::modules::context::build_context_snapshot_for_root(&input.target, input.context_limit)
            .with_context(|| "Could not build context snapshot for threat-model:build")?;
    serde_json::to_string_pretty(&built.snapshot).context("Could not render context snapshot JSON")
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
    let content = read_json_source(&path, "prior threat model")?;
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
    let x_ray = read_required_text(&dir.join(X_RAY_MD), "x-ray source")?;
    let entry_points = read_required_text(&dir.join(X_RAY_ENTRY_POINTS_MD), "x-ray entry points")?;
    let invariants = read_required_text(&dir.join(X_RAY_INVARIANTS_MD), "x-ray invariants")?;
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
    let path = crate::workspace::workspace_state_root(&input.target).join(ENTRY_POINTS_FILE);
    let content = read_json_source(&path, "entry-points artifact")?;
    Ok(ThreatModelSourceRecord::loaded(
        "artifact",
        "entry-points",
        Some(path),
        content,
        input.max_source_bytes,
    ))
}

fn load_design_doc_source(input: &BuildInput, design_doc: &str) -> Result<ThreatModelSourceRecord> {
    let path = resolve_source_path(&input.target, design_doc);
    let content = read_required_text(&path, "designDoc")?;
    Ok(ThreatModelSourceRecord::loaded(
        "operator",
        "designDoc",
        Some(path),
        content,
        input.max_source_bytes,
    ))
}

fn load_seed_source(input: &BuildInput, index: usize, seed: &str) -> Result<ThreatModelSourceRecord> {
    let label = format!("seed-{index}");
    let path = resolve_source_path(&input.target, seed);
    if looks_like_source_path(seed) || path.exists() {
        let content = read_required_text(&path, "seed")?;
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

fn read_json_source(path: &Path, label: &str) -> Result<String> {
    let raw = read_required_text(path, label)?;
    let value: Value = serde_json::from_str(&raw)
        .with_context(|| format!("{label} at {} is not valid JSON", path.display()))?;
    serde_json::to_string_pretty(&value)
        .with_context(|| format!("Could not render {label} from {}", path.display()))
}

fn read_required_text(path: &Path, label: &str) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("Could not read {label} from {}", path.display()))
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
