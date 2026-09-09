use super::super::*;
use super::coverage::CoverageGap;
use std::collections::BTreeMap;

pub(crate) struct GapFillOutcome {
    pub(crate) added_threats: usize,
    pub(crate) added_deprioritized: usize,
    pub(crate) added_entry_points: usize,
    pub(crate) cost_usd: f64,
    pub(crate) cost_usd_exact: bool,
}

/// Stage G: one bounded STRIDE pass over ONLY the uncovered entry points.
/// Gap-fill threats are forced to empty evidence deterministically — "at
/// least one threat with empty evidence, or this stage didn't run".
pub(crate) fn run_gap_fill(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    input: &BuildInput,
    verb: &str,
    gaps: &[CoverageGap],
    document: &mut Value,
    code_evidence: &CodeEvidence,
) -> Result<GapFillOutcome> {
    let prompt = code_evidence.append_to(gap_fill_prompt(input, gaps, document));
    let costed = query_gap_fill(runtime, ctx, input, verb, gaps.len(), prompt)?;
    let outcome = merge_gap_fill(
        document,
        &costed.value,
        gaps,
        costed.cost_usd,
        costed.cost_usd_exact,
    );
    Ok(outcome)
}

fn query_gap_fill(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    input: &BuildInput,
    verb: &str,
    gap_count: usize,
    prompt: String,
) -> Result<crate::structured_output::CostedStructuredJson<Value>> {
    let _scope = begin_gap_fill_scope(ctx, verb, gap_count);
    // The prompt embeds the full gap list, so an unchanged coverage state
    // replays the STRIDE pass for free.
    let cache = crate::semantic_cache::SemanticCache::open_for_target(input.workspace_root());
    crate::structured_output::query_cached_structured_json_with_cost(
        cache.as_ref(),
        runtime,
        AgentQueryRequest::new(
            input.model.clone(),
            input.analysis_root().to_path_buf(),
            threat_model_system_prompt(),
            prompt,
        )
        .with_max_output_tokens(input.max_output_tokens),
        StructuredJsonContract::new(
            "threat-model:build",
            "ThreatModelGapFill",
            gap_fill_schema(),
        ),
        Ok,
    )
    .map(|cached| cached.costed)
}

fn begin_gap_fill_scope(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    gap_count: usize,
) -> Option<crate::run_artifacts::ParentScope> {
    ctx.trace.map(|trace| {
        let phase = trace
            .step(
                "reasoning",
                verb,
                format!("gap-fill: {gap_count} uncovered entry points (STRIDE)"),
            )
            .emit();
        trace.parent_scope(phase)
    })
}

fn gap_fill_schema() -> Value {
    json!({
        "type": "object",
        "required": ["threats", "deprioritized", "entryPoints"],
        "additionalProperties": false,
        "properties": {
            "threats": gap_threat_schema(),
            "deprioritized": gap_deprioritized_schema(),
            "entryPoints": gap_entry_point_schema(),
        }
    })
}

fn gap_threat_schema() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "required": ["id", "targetElementIds", "entryPointIds"],
            "additionalProperties": true,
            "properties": {
                "id": {"type": "string", "minLength": 1},
                "targetElementIds": nonempty_string_array_schema(),
                "entryPointIds": nonempty_string_array_schema(),
            }
        }
    })
}

fn nonempty_string_array_schema() -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "items": {"type": "string", "minLength": 1}
    })
}

fn gap_deprioritized_schema() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "required": ["entryPointId", "entryPoint", "reason"],
            "additionalProperties": true
        }
    })
}

fn gap_entry_point_schema() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "required": ["id", "targetElementIds", "name", "path"],
            "additionalProperties": true
        }
    })
}

fn gap_fill_prompt(input: &BuildInput, gaps: &[CoverageGap], document: &Value) -> String {
    let gap_lines = gaps
        .iter()
        .map(|gap| {
            format!(
                "- id={} · kind={} · name={} · path={}",
                gap.entry_point_id, gap.kind, gap.entry_point, gap.path
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let dfd_elements = gap_fill_dfd_elements(document);
    format!(
        r#"A deterministic coverage check found ground-truth entry points with neither a threat nor a deprioritized row in the threat model for {repo}.

Uncovered entry points:
{gap_lines}

Available DFD elements (use these exact ids in targetElementIds):
{dfd_elements}

For EACH entry point above, walk STRIDE (spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege) and either:
- add the plausible threats as objects with the standard threat shape (id, targetElementIds, entryPointIds, category, title, description, actor, surface, asset, attackVector, preconditions, impact, likelihood, status, existingMitigations, missingMitigations, recommendedMitigation, relatedCwe, affectedFiles) where `entryPointIds` contains the exact AS-* id, `surface` names the entry point verbatim, and `affectedFiles` cites its path. Also return one `entryPoints` row preserving that exact id/name/kind/path and linking it to available DFD elements; or
- add a deprioritized row {{"entryPointId": "<exact AS-* id>", "entryPoint": "<name>", "reason": "<why no material threat>"}}.

Rules:
- Every threat must link to one or more available DFD elements. Never invent a targetElementId.
- Stable entry-point ids are evidence: copy them exactly into threat.entryPointIds, entryPoints[].id, or deprioritized[].entryPointId. Never substitute a path or title for an id.
- Gap-fill threats have NO past-vuln evidence: leave `evidence` empty (it is stripped deterministically).
- Score likelihood from technique prevalence and reachability alone.
- Cover every listed entry point; do not add threats for surfaces not listed.

Return one JSON object: {{"threats": [...], "deprioritized": [...], "entryPoints": [...]}}."#,
        repo = input.repo_name,
    )
}

fn gap_fill_dfd_elements(document: &Value) -> String {
    ["/dfd/nodes", "/dfd/flows", "/dfd/trustBoundaries"]
        .into_iter()
        .flat_map(|pointer| {
            document
                .pointer(pointer)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(gap_fill_dfd_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn gap_fill_dfd_line(element: &Value) -> Option<String> {
    let id = element.get("id").and_then(Value::as_str)?;
    let label = ["name", "description"]
        .into_iter()
        .find_map(|field| element.get(field).and_then(Value::as_str))
        .unwrap_or("unnamed");
    Some(format!("- {id} · {label}"))
}

fn merge_gap_fill(
    document: &mut Value,
    response: &Value,
    gaps: &[CoverageGap],
    cost_usd: f64,
    cost_usd_exact: bool,
) -> GapFillOutcome {
    let allowed = gaps_by_id(gaps);
    let threats = sanitized_gap_threats(response, &allowed);
    let deprioritized = sanitized_deprioritized(response, &allowed);
    let entry_points = sanitized_entry_points(response, &allowed);
    let added_threats = threats.len();
    let added_deprioritized = deprioritized.len();
    append_rows(document, "threats", threats);
    append_rows(document, "deprioritized", deprioritized);
    let added_entry_points = append_entry_points(document, entry_points);
    GapFillOutcome {
        added_threats,
        added_deprioritized,
        added_entry_points,
        cost_usd,
        cost_usd_exact,
    }
}

fn gaps_by_id<'a>(gaps: &'a [CoverageGap]) -> BTreeMap<&'a str, &'a CoverageGap> {
    gaps.iter()
        .map(|gap| (gap.entry_point_id.as_str(), gap))
        .collect()
}

fn sanitized_gap_threats(response: &Value, allowed: &BTreeMap<&str, &CoverageGap>) -> Vec<Value> {
    response
        .get("threats")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|threat| threat_ids_are_allowed(threat, allowed))
        .map(|mut threat| {
            threat["evidence"] = json!([]);
            threat["gapFill"] = json!(true);
            if let Some(name) = single_threat_surface(&threat, allowed) {
                threat["surface"] = json!(name);
            }
            threat
        })
        .collect()
}

fn threat_ids_are_allowed(threat: &Value, allowed: &BTreeMap<&str, &CoverageGap>) -> bool {
    let ids = threat
        .get("entryPointIds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    !ids.is_empty() && ids.iter().all(|id| allowed.contains_key(id))
}

fn single_threat_surface<'a>(
    threat: &Value,
    allowed: &'a BTreeMap<&str, &CoverageGap>,
) -> Option<&'a str> {
    let ids = threat.get("entryPointIds")?.as_array()?;
    (ids.len() == 1)
        .then(|| ids[0].as_str())
        .flatten()
        .and_then(|id| allowed.get(id))
        .map(|gap| gap.entry_point.as_str())
}

fn sanitized_deprioritized(response: &Value, allowed: &BTreeMap<&str, &CoverageGap>) -> Vec<Value> {
    response_rows(response, "deprioritized")
        .filter_map(|mut row| {
            let gap = allowed.get(row.get("entryPointId")?.as_str()?)?;
            row["entryPoint"] = json!(gap.entry_point);
            Some(row)
        })
        .collect()
}

fn sanitized_entry_points(response: &Value, allowed: &BTreeMap<&str, &CoverageGap>) -> Vec<Value> {
    response_rows(response, "entryPoints")
        .filter_map(|mut row| {
            let gap = allowed.get(row.get("id")?.as_str()?)?;
            row["name"] = json!(gap.entry_point);
            row["kind"] = json!(gap.kind);
            row["path"] = json!(gap.path);
            Some(row)
        })
        .collect()
}

fn response_rows<'a>(response: &'a Value, field: &str) -> impl Iterator<Item = Value> + 'a {
    response
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .cloned()
}

fn append_rows(document: &mut Value, key: &str, rows: Vec<Value>) {
    if rows.is_empty() {
        return;
    }
    if !document.get(key).is_some_and(Value::is_array) {
        document[key] = json!([]);
    }
    if let Some(existing) = document.get_mut(key).and_then(Value::as_array_mut) {
        existing.extend(rows);
    }
}

fn append_entry_points(document: &mut Value, rows: Vec<Value>) -> usize {
    if rows.is_empty() {
        return 0;
    }
    let attack_surface = object_field(document, "attackSurface");
    if !attack_surface
        .get("entryPoints")
        .is_some_and(Value::is_array)
    {
        attack_surface.insert("entryPoints".to_string(), json!([]));
    }
    let existing = attack_surface
        .get_mut("entryPoints")
        .and_then(Value::as_array_mut)
        .expect("entryPoints array");
    let before = existing.len();
    append_unique_id_rows(existing, rows);
    existing.len() - before
}

fn object_field<'a>(document: &'a mut Value, key: &str) -> &'a mut serde_json::Map<String, Value> {
    if !document.get(key).is_some_and(Value::is_object) {
        document[key] = json!({});
    }
    document
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .expect("object field")
}

fn append_unique_id_rows(existing: &mut Vec<Value>, rows: Vec<Value>) {
    let mut ids = existing
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<std::collections::BTreeSet<_>>();
    existing.extend(rows.into_iter().filter(|row| {
        row.get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| ids.insert(id.to_string()))
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_fill_threats_are_stripped_of_invented_evidence_and_marked() {
        let mut document = json!({"threats": [{"id": "T-1"}], "deprioritized": []});
        let response = json!({
            "threats": [{
                "id": "T-GAP-1",
                "targetElementIds": ["web"],
                "entryPointIds": ["AS-admin"],
                "surface": "GET /admin/debug",
                "evidence": [{"kind": "commit", "ref": "invented", "summary": "no"}]
            }],
            "deprioritized": [{
                "entryPointId": "AS-health",
                "entryPoint": "GET /health",
                "reason": "no data"
            }],
            "entryPoints": [{
                "id": "AS-admin",
                "targetElementIds": ["web"],
                "name": "GET /admin/debug",
                "path": "src/admin.rs"
            }]
        });
        let gaps = vec![
            gap("AS-admin", "GET /admin/debug", "src/admin.rs"),
            gap("AS-health", "GET /health", "src/health.rs"),
        ];
        let outcome = merge_gap_fill(&mut document, &response, &gaps, 0.1, true);
        assert_eq!(outcome.added_threats, 1);
        assert_eq!(outcome.added_deprioritized, 1);
        assert_eq!(outcome.added_entry_points, 1);
        let added = &document["threats"][1];
        assert_eq!(added["evidence"], json!([]));
        assert_eq!(added["gapFill"], json!(true));
        assert_eq!(
            document["deprioritized"][0]["entryPoint"],
            json!("GET /health")
        );
        assert_eq!(
            document["attackSurface"]["entryPoints"][0]["id"],
            json!("AS-admin")
        );
    }

    #[test]
    fn gap_fill_does_not_duplicate_an_existing_stable_entry_point() {
        let mut document = json!({
            "attackSurface": {"entryPoints": [{"id": "AS-admin", "name": "existing"}]}
        });
        let response = json!({
            "threats": [],
            "deprioritized": [],
            "entryPoints": [{"id": "AS-admin", "name": "duplicate"}]
        });

        let gaps = vec![gap("AS-admin", "GET /admin/debug", "src/admin.rs")];
        let outcome = merge_gap_fill(&mut document, &response, &gaps, 0.0, true);

        assert_eq!(outcome.added_entry_points, 0);
        assert_eq!(
            document["attackSurface"]["entryPoints"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            document["attackSurface"]["entryPoints"][0]["name"],
            json!("existing")
        );
    }

    #[test]
    fn gap_fill_drops_out_of_scope_ids_and_restores_catalog_facts() {
        let mut document = json!({});
        let response = json!({
            "threats": [
                {"id": "T-valid", "entryPointIds": ["AS-admin"], "surface": "forged"},
                {"id": "T-invented", "entryPointIds": ["AS-invented"]}
            ],
            "deprioritized": [
                {"entryPointId": "AS-invented", "entryPoint": "plausible", "reason": "none"}
            ],
            "entryPoints": [
                {"id": "AS-admin", "name": "forged", "kind": "forged", "path": "forged"},
                {"id": "AS-invented", "name": "invented", "path": "invented"}
            ]
        });
        let gaps = vec![gap("AS-admin", "GET /admin/debug", "src/admin.rs")];

        let outcome = merge_gap_fill(&mut document, &response, &gaps, 0.0, true);

        assert_eq!(outcome.added_threats, 1);
        assert_eq!(outcome.added_deprioritized, 0);
        assert_eq!(outcome.added_entry_points, 1);
        assert_eq!(document["threats"][0]["surface"], json!("GET /admin/debug"));
        assert_eq!(
            document["attackSurface"]["entryPoints"][0]["name"],
            json!("GET /admin/debug")
        );
        assert_eq!(
            document["attackSurface"]["entryPoints"][0]["kind"],
            json!("http-route")
        );
        assert_eq!(
            document["attackSurface"]["entryPoints"][0]["path"],
            json!("src/admin.rs")
        );
    }

    fn gap(id: &str, name: &str, path: &str) -> CoverageGap {
        CoverageGap {
            entry_point_id: id.to_string(),
            entry_point: name.to_string(),
            kind: "http-route".to_string(),
            path: path.to_string(),
        }
    }
}
