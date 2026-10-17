use super::*;
use crate::content_store::{ContentStore, ObjectKind};
use crate::workspace::source_snapshot::SourceSnapshot;

mod context;
mod persistence;
mod validation;
pub(super) use self::persistence::archive_profile;
pub(super) use self::persistence::{catalog_lock, selected_catalog};
mod render;
#[cfg(test)]
mod tests;

const MAX_DRAFT_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const TOOL: &str = "taint-iris-next:catalog";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogDraft {
    schema_version: u32,
    kind: String,
    target: String,
    source_tree_hash: String,
    source_snapshot_hash: String,
    model: String,
    base_catalog_digest: Option<String>,
    catalog: Vec<Value>,
    inspection: Value,
    frozen_input: Value,
    system_prompt: String,
}

struct DraftOrigin {
    model: String,
    base: Option<String>,
    system: String,
}

pub(crate) fn run_taint_iris_next_catalog_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    let runtime = require_taint_iris_next_runtime(runtime)?;
    let model = require_taint_iris_next_model(input, ctx)?;
    let snapshot = SourceSnapshot::capture(ctx, TOOL, &target)?;
    let base = persistence::active_digest(&target)?;
    let prepared = context::prepare(&target, input, ctx)?;
    let system = optional_taint_next_string(input, &["TAINT_IRIS_NEXT_CATALOG_PROMPT"])?
        .unwrap_or_else(|| TAINT_IRIS_NEXT_CATALOG_SYSTEM_PROMPT.into());
    anyhow::ensure!(
        system.len() <= 16 * 1024,
        "Catalog system prompt exceeds 16 KiB"
    );
    let retained_bound = serde_json::to_vec(&prepared.inspection)?.len()
        + prepared.prompt.len()
        + system.len()
        + MAX_RESPONSE_BYTES
        + 16 * 1024;
    anyhow::ensure!(retained_bound <= MAX_DRAFT_BYTES, "Coverage and frozen inputs exceed the retainable draft size; refine the source scope before model work");
    let origin = DraftOrigin {
        model: model.clone(),
        base,
        system: system.clone(),
    };
    let response = super::dynamic_catalog::query_catalog_agent(
        runtime,
        model.clone(),
        &target,
        system,
        prepared.prompt.clone(),
    )?;
    let cost = response.checked_cost_report()?;
    let raw_output = bounded_response(&response).ok();
    let raw_text = context::prefix(&response.text, MAX_RESPONSE_BYTES);
    let raw_text_truncated = raw_text.len() < response.text.len();
    let frozen_input: Value = serde_json::from_str(&prepared.prompt)?;
    let retained_system = origin.system.clone();
    let result = finish_generation(&target, &snapshot, origin, prepared, response, ctx);
    let mut result = result
        .unwrap_or_else(|error| render::failed(&format!("Draft could not be retained: {error:#}")));
    result["data"]["rawAgentOutput"] = json!(raw_output);
    result["data"]["rawAgentText"] = json!(raw_text);
    result["data"]["rawAgentTextTruncated"] = json!(raw_text_truncated);
    result["data"]["frozenInput"] = frozen_input;
    result["data"]["systemPrompt"] = json!(retained_system);
    result["data"]["sourceCheckCurrent"] = json!(result["status"] != "failed");
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(snapshot.attach(result))
}

fn finish_generation(
    root: &Path,
    snapshot: &SourceSnapshot,
    origin: DraftOrigin,
    prepared: context::PreparedCatalog,
    response: AgentQueryResponse,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let raw = bounded_response(&response)?;
    let entries = validation::validate(&raw, &prepared.sources)?;
    let draft = CatalogDraft {
        schema_version: 1,
        kind: "taint-catalog-draft".into(),
        target: root.canonicalize()?.to_string_lossy().into(),
        source_tree_hash: snapshot.hashes().1.into(),
        source_snapshot_hash: snapshot.hashes().0.into(),
        model: origin.model,
        base_catalog_digest: origin.base,
        catalog: entries,
        inspection: prepared.inspection,
        frozen_input: serde_json::from_str(&prepared.prompt)?,
        system_prompt: origin.system,
    };
    anyhow::ensure!(!ctx.is_cancelled(), "Catalog draft canceled before save");
    snapshot.ensure_current(ctx, TOOL, root)?;
    let reference = persistence::save(root, &draft)?;
    let mut result = render::draft(&draft, &reference)?;
    result["artifacts"] = json!([persistence::artifact(
        root,
        &reference,
        "Immutable taint catalog draft"
    )?]);
    Ok(result)
}

fn bounded_response(response: &AgentQueryResponse) -> Result<Value> {
    anyhow::ensure!(
        response.text.len() <= MAX_RESPONSE_BYTES,
        "Catalog response exceeds 64 KiB; prior catalog is unchanged"
    );
    if let Some(value) = &response.structured {
        anyhow::ensure!(
            serde_json::to_vec(value)?.len() <= MAX_RESPONSE_BYTES,
            "Structured catalog response exceeds 64 KiB"
        );
    }
    super::dynamic_catalog::catalog_raw_value(response)
        .context("Model did not return a JSON catalog; no repair request was made")
}

pub(crate) fn read_catalog_draft(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = resolve_tool_target(input, ctx)?;
    if input.get("draftRef").is_none() {
        return read_profile(&root, input);
    }
    anyhow::ensure!(
        input.get("catalogDigestRef").is_none(),
        "Choose draftRef or catalogDigestRef, not both"
    );
    let reference = persistence::reference(input)?;
    let draft = persistence::load(&root, &reference)?;
    if input["section"] == "inputs" {
        return render::inputs(&draft, &reference);
    }
    render::draft(&draft, &reference)
}

fn read_profile(root: &Path, input: &Value) -> Result<Value> {
    let Some((reference, bytes)) =
        persistence::raw_profile(root, input["catalogDigestRef"].as_str())?
    else {
        return Ok(crate::module_result::completed_output_result("No saved taint catalog", "No active catalog. Built-in patterns remain available. Catalog generation requires a separately approved Context allowance.", json!({"status":"absent","expectedActiveDigest":"absent","sourceFreshnessVerified":false})));
    };
    let value = match persistence::parse_profile(root, &bytes) {
        Ok(value) => value,
        Err(error) => return Ok(render::unreadable(&reference, &error)),
    };
    if input["section"] == "inputs" {
        let draft = value["acceptedDraftRef"].as_str().context(
            "Legacy catalog has no frozen model inputs; inspect its recorded import instead",
        )?;
        return render::inputs(&persistence::load(root, draft)?, draft);
    }
    render::profile(&value, &reference)
}

pub(crate) fn accept_catalog_draft(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = resolve_tool_target(input, ctx)?;
    let reference = persistence::reference(input)?;
    let draft = persistence::load(&root, &reference)?;
    anyhow::ensure!(draft.inspection["status"] != "partial" || input["acknowledgePartial"] == true,
        "Catalog context is partial; inspect it, then explicitly acknowledgePartial before acceptance");
    let accepted = persistence::accept(
        &root,
        &reference,
        &draft,
        ctx,
        input["expectedActiveDigest"].as_str(),
    )?;
    let digest = &accepted.digest;
    let mut result = crate::module_result::completed_output_result("Taint catalog accepted",
        format!("Accepted reviewed catalog: {}.\nPin catalogDigestRef={digest} in a separately approved scan plan.\nNo scan or model request started.", render::entries_count(draft.catalog.len())),
        json!({"status":"accepted","draftRef":reference,"catalogDigestRef":digest,"entries":draft.catalog,"sourceTreeHash":draft.source_tree_hash,"activeCatalogChanged":accepted.changed,"previousCatalogDigestRef":accepted.previous_digest}));
    let mut artifacts = vec![persistence::artifact(
        &root,
        digest,
        "Immutable accepted taint catalog",
    )?];
    if let Some(previous) = &accepted.previous_digest {
        let mut artifact = persistence::artifact(&root, previous, "Previous catalog bytes")?;
        artifact["kind"] = json!("text");
        artifacts.push(artifact);
    }
    result["artifacts"] = json!(artifacts);
    Ok(result)
}
