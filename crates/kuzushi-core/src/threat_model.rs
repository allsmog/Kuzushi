use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime};

const VALID_STAGES: &[&str] = &["s1", "s2", "s3", "s4"];
const VALID_METHODOLOGIES: &[&str] = &["pasta", "stride", "dread"];
const STRIDE_CATEGORIES: &[&str] = &[
    "spoofing",
    "tampering",
    "repudiation",
    "information-disclosure",
    "denial-of-service",
    "elevation-of-privilege",
];

pub fn execute_threat_model_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match name {
        "threat-model:build" => build_threat_model(input, ctx, runtime, BuildFlavor::ThreatModel),
        "randori:pasta" => build_threat_model(input, ctx, runtime, BuildFlavor::RandoriPasta),
        "threat-model:read" => read_threat_model(input, ctx, ReadFlavor::ThreatModel),
        "randori:threat-model" => read_threat_model(input, ctx, ReadFlavor::Randori),
        "threat-model:methodologies" => Ok(methodologies_output()),
        other => anyhow::bail!("unknown threat-model tool {other:?}"),
    }
}

#[derive(Debug, Clone, Copy)]
enum BuildFlavor {
    ThreatModel,
    RandoriPasta,
}

impl BuildFlavor {
    fn tool_name(self) -> &'static str {
        match self {
            Self::ThreatModel => "threat-model:build",
            Self::RandoriPasta => "randori:pasta",
        }
    }

    fn default_artifact_leaf(self) -> &'static str {
        match self {
            Self::ThreatModel => "threat-model-output",
            Self::RandoriPasta => "randori-output",
        }
    }

    fn provider(self) -> &'static str {
        "randori-pasta"
    }

    fn persists_document(self) -> bool {
        matches!(self, Self::ThreatModel)
    }
}

#[derive(Debug, Clone, Copy)]
enum ReadFlavor {
    ThreatModel,
    Randori,
}

impl ReadFlavor {
    fn tool_name(self) -> &'static str {
        match self {
            Self::ThreatModel => "threat-model:read",
            Self::Randori => "randori:threat-model",
        }
    }
}

#[derive(Debug)]
struct BuildInput {
    target: PathBuf,
    repo_name: String,
    methodology: String,
    slice: String,
    stages: Vec<String>,
    output_dir: String,
    max_elements: usize,
    max_threats: usize,
    emit_findings: bool,
    preserve_user_edits: bool,
    model: String,
}

fn build_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    flavor: BuildFlavor,
) -> Result<Value> {
    let runtime = runtime.with_context(|| {
        format!(
            "{} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
            flavor.tool_name()
        )
    })?;
    let input = parse_build_input(&input, ctx, flavor)?;
    let previous_model = load_persistent_threat_model(&input.target);
    let prompt = build_agent_prompt(&input, previous_model.as_ref())?;
    let response = runtime.query_blocking(AgentQueryRequest {
        model: input.model.clone(),
        cwd: input.target.clone(),
        system_prompt: THREAT_MODEL_SYSTEM_PROMPT.to_string(),
        prompt,
    })?;

    let raw = match response.structured {
        Some(value) => value,
        None => parse_json_from_agent_text(&response.text).with_context(|| {
            format!(
                "{} expected pi-agent-core to return a JSON ThreatModelDocument",
                flavor.tool_name()
            )
        })?,
    };
    let (document_candidate, bridge_findings) = extract_document_and_findings(raw)?;
    let document = normalize_document(document_candidate, &input.methodology)?;
    let document = apply_methodology(document, &input.methodology)?;
    let normalized_artifact =
        write_normalized_artifact(&input.target, &input.output_dir, &document)?;
    let persisted = if flavor.persists_document() {
        save_persistent_threat_model(&input.target, &document, !input.preserve_user_edits)?
    } else {
        false
    };
    let findings = if input.emit_findings {
        build_findings_from_document(&document)
    } else {
        bridge_findings.unwrap_or_else(Vec::new)
    };

    let threat_count = array_len(document.pointer("/threats"));
    let node_count = array_len(document.pointer("/dfd/nodes"));
    let flow_count = array_len(document.pointer("/dfd/flows"));
    let boundary_count = array_len(document.pointer("/dfd/trustBoundaries"));
    let mut lines = match flavor {
        BuildFlavor::ThreatModel => vec![
            format!(
                "threat-model:build complete for {} ({})",
                input.repo_name,
                input.target.display()
            ),
            format!("  Method:   {}", methodology_label(&input.methodology)),
            format!("  Slice:    {}", input.slice),
            format!("  Provider: {}", flavor.provider()),
            format!("  Stages:   {}", input.stages.join(", ")),
            format!("  Artifact: {}", input.output_dir),
            format!(
                "  Saved:    {}",
                if persisted {
                    ".kuzushi/threat-model.json"
                } else {
                    "skipped (operator-edited model preserved)"
                }
            ),
        ],
        BuildFlavor::RandoriPasta => vec![
            format!(
                "randori:pasta complete for {} ({})",
                input.repo_name,
                input.target.display()
            ),
            format!("  Stages:   {}", input.stages.join(", ")),
            format!("  Artifact: {}", input.output_dir),
        ],
    };
    lines.extend([
        format!("  Threats:  {threat_count}"),
        format!(
            "  DFD:      {node_count} nodes · {flow_count} flows · {boundary_count} boundaries"
        ),
        format!(
            "  Findings: {}{}",
            findings.len(),
            if input.emit_findings {
                ""
            } else {
                " (emitFindings=false)"
            }
        ),
        "  Cost:     $0.0000".to_string(),
    ]);
    append_top_threats(&mut lines, &document);

    Ok(json!({
        "ok": threat_count > 0 || node_count > 0 || flow_count > 0,
        "output": lines.join("\n"),
        "data": {
            "target": input.target.display().to_string(),
            "repoName": input.repo_name,
            "artifactDir": input.output_dir,
            "normalizedArtifact": normalized_artifact.display().to_string(),
            "threatModelPath": input.target.join(".kuzushi").join("threat-model.json").display().to_string(),
            "provider": flavor.provider(),
            "methodology": input.methodology,
            "slice": input.slice,
            "stages": input.stages,
            "document": document,
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}

fn parse_build_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<BuildInput> {
    let target = resolve_target(input, ctx)?;
    let repo_name = repo_name(&target);
    let methodology = read_methodology(input, "pasta");
    let slice = read_string(input, &["slice"])
        .filter(|value| {
            matches!(
                value.as_str(),
                "all" | "dfd" | "stride" | "stories" | "scope" | "scenarios"
            )
        })
        .unwrap_or_else(|| "all".to_string());
    let stages = read_stages(input, flavor.tool_name())?;
    let run_id = Uuid::new_v4().to_string();
    let output_dir = read_string(input, &["outputDir", "output_dir"])
        .unwrap_or_else(|| format!(".kuzushi/runs/{run_id}/{}", flavor.default_artifact_leaf()));
    let max_elements = read_usize(input, &["maxElements", "max_elements"], 40, 5);
    let max_threats = read_usize(input, &["maxThreats", "max_threats"], 30, 1);
    let emit_findings = read_bool(input, &["emitFindings", "emit_findings"], false);
    let preserve_user_edits = read_bool(input, &["preserveUserEdits", "preserve_user_edits"], true);
    let model = read_string(input, &["model"])
        .or_else(|| ctx.config.model.clone())
        .with_context(|| {
            format!(
                "{} requires an explicit model in config.toml, KUZUSHI_MODEL, or the tool input; Kuzushi will not choose a fallback model",
                flavor.tool_name()
            )
        })?;

    Ok(BuildInput {
        target,
        repo_name,
        methodology,
        slice,
        stages,
        output_dir,
        max_elements,
        max_threats,
        emit_findings,
        preserve_user_edits,
        model,
    })
}

fn read_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: ReadFlavor,
) -> Result<Value> {
    let output_dir = match read_string(&input, &["outputDir", "output_dir"]) {
        Some(value) => value,
        None => {
            return Ok(json!({
                "ok": false,
                "output": format!("{} requires an outputDir.", flavor.tool_name()),
            }));
        }
    };
    let target = resolve_target(&input, ctx)?;
    let repo_name = repo_name(&target);
    let methodology = read_methodology(&input, "pasta");
    let artifacts = read_randori_artifacts(&target, &output_dir);
    let normalized_path =
        resolve_output_dir(&target, &output_dir).join("normalized-threat-model.json");
    let document = if normalized_path.exists() {
        let raw = fs::read_to_string(&normalized_path)
            .with_context(|| format!("Could not read {}", normalized_path.display()))?;
        let parsed = serde_json::from_str::<Value>(&raw)
            .with_context(|| format!("Could not parse {}", normalized_path.display()))?;
        Some(normalize_document(parsed, &methodology)?)
    } else if artifacts.has_any_artifact() {
        convert_randori_artifacts_to_document(&artifacts, &methodology)?
    } else {
        None
    };

    let Some(document) = document else {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "No threat-model artifacts found under {} (resolved against {}).",
                output_dir,
                target.display()
            ),
        }));
    };
    let document = apply_methodology(document, &methodology)?;
    let threat_count = array_len(document.pointer("/threats"));
    let node_count = array_len(document.pointer("/dfd/nodes"));
    let flow_count = array_len(document.pointer("/dfd/flows"));
    let output = match flavor {
        ReadFlavor::ThreatModel => format!(
            "Loaded {} threat model for {} from {}\n  Threats: {}\n  DFD:     {} nodes · {} flows",
            methodology_label(&methodology),
            repo_name,
            output_dir,
            threat_count,
            node_count,
            flow_count
        ),
        ReadFlavor::Randori => format!(
            "Loaded threat model for {} from {}\n  Threats: {}\n  DFD:     {} nodes · {} flows",
            repo_name, output_dir, threat_count, node_count, flow_count
        ),
    };

    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "target": target.display().to_string(),
            "repoName": repo_name,
            "outputDir": output_dir,
            "methodology": methodology,
            "document": document,
            "artifacts": artifacts.to_json(),
        },
    }))
}

fn methodologies_output() -> Value {
    let output = [
        "Selectable threat model methodologies:",
        "- pasta: risk-first PASTA flow using Randori stages S1-S4 plus narrative synthesis.",
        "- stride: DFD + bounded STRIDE threat scenarios from the same evidence-grounded provider.",
        "- dread: DREAD risk scoring overlay over generated threat scenarios.",
    ]
    .join("\n");
    json!({
        "ok": true,
        "output": output,
        "data": {
            "methodologies": VALID_METHODOLOGIES,
            "provider": "randori-pasta",
        },
    })
}

const THREAT_MODEL_SYSTEM_PROMPT: &str = r#"You are Kuzushi's threat-modeling agent.
Return only JSON. Produce a normalized ThreatModelDocument with:
{"version":"2.0","dfd":{"nodes":[],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{"total":0,"bySeverity":{},"byCategory":{}}}
Use camelCase field names from the schema. Do not include markdown."#;

fn build_agent_prompt(input: &BuildInput, previous_model: Option<&Value>) -> Result<String> {
    let files = inventory_files(&input.target, input.max_elements.saturating_mul(4).max(40))?;
    let manifest_summary = read_manifest_summary(&input.target)?;
    let previous_summary = previous_model.map(|model| {
        json!({
            "nodes": array_len(model.pointer("/dfd/nodes")),
            "flows": array_len(model.pointer("/dfd/flows")),
            "threats": array_len(model.pointer("/threats")),
            "userEdited": model.get("userEdited").and_then(Value::as_bool).unwrap_or(false),
        })
    });
    Ok(format!(
        r#"Build a repository threat model.

Target: {target}
Repository name: {repo_name}
Methodology: {methodology}
Slice: {slice}
Stages: {stages}
Max DFD elements: {max_elements}
Max threats: {max_threats}

Repository inventory:
{files}

Manifest summary:
{manifest_summary}

Previous persistent model summary:
{previous_summary}

Return a single JSON object representing ThreatModelDocument. Include at least:
- dfd.nodes with id, type, name, description, trustZone
- dfd.flows with id, description, sourceId, targetId, trustBoundaryIds
- dfd.trustBoundaries with id, name, innerZone, outerZone, crossingFlowIds
- threats with id, targetElementIds, category, title, description, attackVector, preconditions, impact, likelihood, existingMitigations, missingMitigations, relatedCwe, affectedFiles
"#,
        target = input.target.display(),
        repo_name = input.repo_name,
        methodology = input.methodology,
        slice = input.slice,
        stages = input.stages.join(", "),
        max_elements = input.max_elements,
        max_threats = input.max_threats,
        files = files.join("\n"),
        manifest_summary = manifest_summary,
        previous_summary = previous_summary
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string()),
    ))
}

#[derive(Debug, Clone)]
struct RandoriArtifacts {
    state: Option<Value>,
    s1_objectives: Option<Value>,
    s2_scope: Option<Value>,
    s3_decomposition: Option<Value>,
    s4_threats: Option<Value>,
    narrative: Option<Value>,
}

impl RandoriArtifacts {
    fn has_any_artifact(&self) -> bool {
        self.state.is_some()
            || self.s1_objectives.is_some()
            || self.s2_scope.is_some()
            || self.s3_decomposition.is_some()
            || self.s4_threats.is_some()
            || self.narrative.is_some()
    }

    fn to_json(&self) -> Value {
        json!({
            "state": self.state,
            "s1Objectives": self.s1_objectives,
            "s2Scope": self.s2_scope,
            "s3Decomposition": self.s3_decomposition,
            "s4Threats": self.s4_threats,
            "narrative": self.narrative,
        })
    }
}

fn read_randori_artifacts(root: &Path, output_dir: &str) -> RandoriArtifacts {
    let dir = resolve_output_dir(root, output_dir);
    RandoriArtifacts {
        state: read_json_optional(&dir.join("randori-state.json")),
        s1_objectives: read_json_optional(&dir.join("pasta-s1.json")),
        s2_scope: read_json_optional(&dir.join("pasta-s2.json")),
        s3_decomposition: read_json_optional(&dir.join("pasta-s3.json")),
        s4_threats: read_json_optional(&dir.join("pasta-s4.json")),
        narrative: read_json_optional(&dir.join("pasta-narrative.json")),
    }
}

fn convert_randori_artifacts_to_document(
    artifacts: &RandoriArtifacts,
    methodology: &str,
) -> Result<Option<Value>> {
    if artifacts.s2_scope.is_none()
        && artifacts.s3_decomposition.is_none()
        && artifacts.s4_threats.is_none()
    {
        return Ok(None);
    }

    let mut nodes = BTreeMap::<String, Value>::new();
    let mut flows = BTreeMap::<String, Value>::new();
    let mut trust_boundaries = BTreeMap::<String, Value>::new();

    if let Some(s2) = artifacts.s2_scope.as_ref().and_then(Value::as_object) {
        for actor in records(s2.get("actors")) {
            let Some(id) = str_field(actor, &["id"]) else {
                continue;
            };
            let name = str_field(actor, &["name"]).unwrap_or_else(|| id.clone());
            insert_node(
                &mut nodes,
                &id,
                actor_type_to_dfd_type(str_field(actor, &["type"]).as_deref().unwrap_or("")),
                &name,
                str_field(actor, &["description"])
                    .as_deref()
                    .unwrap_or(&name),
                str_field(actor, &["trust_zone", "trustZone", "trust_level"])
                    .as_deref()
                    .unwrap_or("external"),
            );
        }
        for service in records(s2.get("services")) {
            let Some(id) = str_field(service, &["id"]) else {
                continue;
            };
            let name = str_field(service, &["name"]).unwrap_or_else(|| id.clone());
            insert_node(
                &mut nodes,
                &id,
                "process",
                &name,
                str_field(service, &["description"])
                    .as_deref()
                    .unwrap_or(&name),
                "internal",
            );
        }
        for database in records(s2.get("databases")) {
            let Some(id) = str_field(database, &["id"]) else {
                continue;
            };
            let name = str_field(database, &["name"]).unwrap_or_else(|| id.clone());
            insert_node(
                &mut nodes,
                &id,
                "data-store",
                &name,
                str_field(database, &["description"])
                    .as_deref()
                    .unwrap_or(&name),
                "internal",
            );
        }
        if let Some(components) = s2.get("components").and_then(Value::as_object) {
            for (kind, list) in components {
                for component in records(Some(list)) {
                    let Some(id) = str_field(component, &["id", "name"]) else {
                        continue;
                    };
                    let name = str_field(component, &["name"]).unwrap_or_else(|| id.clone());
                    insert_node(
                        &mut nodes,
                        &id,
                        component_kind_to_dfd_type(kind),
                        &name,
                        str_field(component, &["description"])
                            .as_deref()
                            .unwrap_or(kind),
                        str_field(component, &["trust_zone", "trustZone"])
                            .as_deref()
                            .unwrap_or("internal"),
                    );
                }
            }
        }
        collect_flows(s2.get("data_flows"), &mut flows);
    }

    if let Some(s3) = artifacts
        .s3_decomposition
        .as_ref()
        .and_then(Value::as_object)
    {
        for (key, default_type, default_zone) in [
            ("external_entities", "external-entity", "external"),
            ("entry_points", "process", "entrypoint"),
            ("processes", "process", "internal"),
            ("data_stores", "data-store", "internal"),
        ] {
            for item in records(s3.get(key)) {
                let Some(id) = str_field(item, &["id"]) else {
                    continue;
                };
                let name = str_field(item, &["name"]).unwrap_or_else(|| id.clone());
                insert_node(
                    &mut nodes,
                    &id,
                    default_type,
                    &name,
                    str_field(item, &["description", "notes"])
                        .as_deref()
                        .unwrap_or(&name),
                    str_field(item, &["trust_zone", "trustZone"])
                        .as_deref()
                        .unwrap_or(default_zone),
                );
            }
        }
        for item in records_or_record_collections(s3.get("dfd_elements")) {
            let Some(id) = str_field(item, &["id"]) else {
                continue;
            };
            let name = str_field(item, &["name"]).unwrap_or_else(|| id.clone());
            insert_node(
                &mut nodes,
                &id,
                normalize_dfd_type(str_field(item, &["type"]).as_deref().unwrap_or("process")),
                &name,
                str_field(item, &["description"])
                    .as_deref()
                    .unwrap_or(&name),
                str_field(item, &["trust_zone", "trustZone", "component"])
                    .as_deref()
                    .unwrap_or("unknown"),
            );
        }
        collect_flows(s3.get("data_flows"), &mut flows);
        for boundary in records(s3.get("trust_boundaries")) {
            let Some(id) = str_field(boundary, &["id"]) else {
                continue;
            };
            let name = str_field(boundary, &["name"]).unwrap_or_else(|| id.clone());
            let mut crossings = string_array_field(
                boundary,
                &[
                    "crossing_flow_ids",
                    "crossingFlowIds",
                    "crossing_flows",
                    "flows",
                ],
            );
            for flow in flows.values() {
                let includes = flow
                    .get("trustBoundaryIds")
                    .and_then(Value::as_array)
                    .is_some_and(|ids| ids.iter().any(|value| value.as_str() == Some(&id)));
                if includes {
                    if let Some(flow_id) = flow.get("id").and_then(Value::as_str) {
                        crossings.push(flow_id.to_string());
                    }
                }
            }
            crossings.sort();
            crossings.dedup();
            trust_boundaries.insert(
                id.clone(),
                json!({
                    "id": id,
                    "name": name,
                    "innerZone": str_field(boundary, &["inner_zone", "innerZone"]).unwrap_or_else(|| "internal".to_string()),
                    "outerZone": str_field(boundary, &["outer_zone", "outerZone"]).unwrap_or_else(|| "external".to_string()),
                    "crossingFlowIds": crossings,
                }),
            );
        }
    }

    let threats = artifacts
        .s4_threats
        .as_ref()
        .and_then(Value::as_object)
        .map(parse_threats)
        .unwrap_or_default();
    let narrative = artifacts.narrative.as_ref().and_then(parse_narrative);
    let summary = build_summary(&threats);
    let document = json!({
        "version": "2.0",
        "methodology": methodology,
        "dfd": {
            "nodes": nodes.into_values().collect::<Vec<_>>(),
            "flows": flows.into_values().collect::<Vec<_>>(),
            "trustBoundaries": trust_boundaries.into_values().collect::<Vec<_>>(),
        },
        "threats": threats,
        "summary": summary,
    });
    let mut document = normalize_document(document, methodology)?;
    if let Some(narrative) = narrative {
        if let Some(object) = document.as_object_mut() {
            object.insert("narrative".to_string(), narrative);
        }
    }
    Ok(Some(document))
}

fn collect_flows(raw: Option<&Value>, flows: &mut BTreeMap<String, Value>) {
    for item in records(raw) {
        let Some(id) = str_field(item, &["id"]) else {
            continue;
        };
        let Some(source) = str_field(item, &["source_id", "sourceId", "source", "from"]) else {
            continue;
        };
        let Some(target) = str_field(
            item,
            &["target_id", "targetId", "target", "destination", "to"],
        ) else {
            continue;
        };
        let name = str_field(item, &["name", "label", "data"])
            .unwrap_or_else(|| format!("{source} -> {target}"));
        flows.entry(id.clone()).or_insert_with(|| {
            let trust_boundary_ids =
                string_array_field(item, &["trust_boundary_ids", "trustBoundaryIds", "crosses"]);
            json!({
                "id": id,
                "name": name,
                "description": str_field(item, &["description"]).unwrap_or_else(|| name.clone()),
                "sourceId": source,
                "targetId": target,
                "protocol": str_field(item, &["protocol"]).unwrap_or_default(),
                "dataClassification": str_field(item, &["data_classification", "dataClassification", "classification", "sensitivity"]).unwrap_or_default(),
                "trustBoundaryIds": trust_boundary_ids,
            })
        });
    }
}

fn insert_node(
    nodes: &mut BTreeMap<String, Value>,
    id: &str,
    node_type: &str,
    name: &str,
    description: &str,
    trust_zone: &str,
) {
    if node_type == "data-flow" {
        return;
    }
    nodes.entry(id.to_string()).or_insert_with(|| {
        json!({
            "id": id,
            "type": node_type,
            "name": name,
            "description": description,
            "trustZone": trust_zone,
        })
    });
}

fn parse_threats(s4: &Map<String, Value>) -> Vec<Value> {
    let raw = s4
        .get("threat_scenarios")
        .or_else(|| s4.get("threats"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for item in raw {
        let Some(record) = item.as_object() else {
            continue;
        };
        let Some(id) = str_field(record, &["id"]) else {
            continue;
        };
        let title = str_field(record, &["title", "name"]).unwrap_or_else(|| id.clone());
        let Some(category) = normalize_stride_category(
            str_field(record, &["stride_category", "category"])
                .as_deref()
                .unwrap_or(""),
        ) else {
            continue;
        };
        let target_element_ids = nonempty_string_array(
            string_array_field(
                record,
                &[
                    "target_element_ids",
                    "targetElementIds",
                    "target_assets",
                    "affected_components",
                ],
            ),
            "unknown",
        );
        let evidence_anchors = parse_evidence_anchors(
            record
                .get("evidence_anchors")
                .or_else(|| record.get("evidenceAnchors")),
        );
        let affected_files = evidence_anchors
            .iter()
            .filter_map(|anchor| {
                Some(json!({
                    "filePath": anchor.get("filePath")?.as_str()?,
                    "startLine": anchor.get("startLine")?.as_u64().unwrap_or(1),
                }))
            })
            .collect::<Vec<_>>();
        let probability = record
            .get("probability")
            .and_then(Value::as_f64)
            .unwrap_or(0.5);
        out.push(json!({
            "id": id,
            "targetElementIds": target_element_ids,
            "actorIds": string_array_field(record, &["actor_ids", "actorIds", "actors"]),
            "entrypointIds": string_array_field(record, &["entrypoint_ids", "entrypointIds", "entry_points"]),
            "flowIds": string_array_field(record, &["flow_ids", "flowIds", "flows"]),
            "category": category,
            "title": title,
            "description": str_field(record, &["description"]).unwrap_or_else(|| title.clone()),
            "attackVector": str_field(record, &["attack_technique_id", "attackTechniqueId", "mitre_attack", "attack_scenario"]).unwrap_or_else(|| "unknown".to_string()),
            "preconditions": string_array_field(record, &["gaps", "preconditions"]),
            "impact": normalize_impact(str_field(record, &["impact"]).as_deref().unwrap_or("medium")),
            "likelihood": probability_to_likelihood(probability),
            "probability": probability,
            "existingMitigations": string_array_field(record, &["existing_controls", "existingMitigations"]),
            "missingMitigations": string_array_field(record, &["recommended_mitigations", "missingMitigations", "recommended_remediation"]),
            "relatedCwe": build_cwe_list(record),
            "affectedFiles": affected_files,
            "evidenceAnchors": evidence_anchors,
            "sources": parse_references(record.get("sources"), "source"),
            "sinks": parse_references(record.get("sinks"), "sink"),
            "guards": parse_references(record.get("guards"), "guard"),
            "sanitizers": parse_references(record.get("sanitizers"), "sanitizer"),
            "requiredCapabilities": string_array_field(record, &["required_capabilities", "requiredCapabilities"]),
            "elementId": str_field(record, &["element_id", "elementId"]).unwrap_or_else(|| "unknown".to_string()),
        }));
    }
    out
}

fn parse_evidence_anchors(raw: Option<&Value>) -> Vec<Value> {
    raw.and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let record = item.as_object()?;
                    let file_path = str_field(record, &["file_path", "filePath"])?;
                    let description = str_field(record, &["description"])?;
                    Some(json!({
                        "filePath": file_path,
                        "startLine": number_field(record, &["start_line", "startLine"]).unwrap_or(1),
                        "endLine": number_field(record, &["end_line", "endLine"]),
                        "symbol": str_field(record, &["symbol"]),
                        "description": description,
                        "snippet": str_field(record, &["snippet"]),
                        "source": str_field(record, &["source"]),
                    }))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_references(raw: Option<&Value>, fallback_kind: &str) -> Vec<Value> {
    raw.and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let record = item.as_object()?;
                    Some(json!({
                        "kind": str_field(record, &["kind"]).unwrap_or_else(|| fallback_kind.to_string()),
                        "name": str_field(record, &["name"]),
                        "elementId": str_field(record, &["element_id", "elementId"]),
                        "filePath": str_field(record, &["file_path", "filePath"]),
                        "startLine": number_field(record, &["start_line", "startLine"]),
                        "endLine": number_field(record, &["end_line", "endLine"]),
                        "symbol": str_field(record, &["symbol"]),
                        "description": str_field(record, &["description"]),
                        "snippet": str_field(record, &["snippet"]),
                        "source": str_field(record, &["source"]),
                    }))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_narrative(raw: &Value) -> Option<Value> {
    let record = raw.as_object()?;
    let overview = str_field(record, &["overview"]).unwrap_or_default();
    let input_categories = record
        .get("input_categories")
        .or_else(|| record.get("inputCategories"))
        .and_then(Value::as_object);
    let criticality = record
        .get("criticality_buckets")
        .or_else(|| record.get("criticalityBuckets"))
        .and_then(Value::as_object);
    let attacker_stories = record
        .get("attacker_stories")
        .or_else(|| record.get("attackerStories"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let story = item.as_object()?;
                    let title = str_field(story, &["title"])?;
                    let narrative = str_field(story, &["narrative"])?;
                    Some(json!({
                        "title": title,
                        "narrative": narrative,
                        "mitigation": str_field(story, &["mitigation"]).unwrap_or_default(),
                        "threatIds": string_array_field(story, &["threat_ids", "threatIds"]),
                    }))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let out_of_scope = string_array_field(record, &["out_of_scope", "outOfScope"]);
    let has_content =
        !overview.is_empty() || !attacker_stories.is_empty() || !out_of_scope.is_empty();
    if !has_content {
        return None;
    }
    Some(json!({
        "overview": overview,
        "inputCategories": {
            "attackerControlled": input_categories.map(|r| string_array_field(r, &["attacker_controlled", "attackerControlled"])).unwrap_or_default(),
            "operatorControlled": input_categories.map(|r| string_array_field(r, &["operator_controlled", "operatorControlled"])).unwrap_or_default(),
            "developerControlled": input_categories.map(|r| string_array_field(r, &["developer_controlled", "developerControlled"])).unwrap_or_default(),
            "externalServices": input_categories.map(|r| string_array_field(r, &["external_services", "externalServices"])).unwrap_or_default(),
            "sandboxBoundary": input_categories.map(|r| string_array_field(r, &["sandbox_boundary", "sandboxBoundary"])).unwrap_or_default(),
            "assumptions": input_categories.map(|r| string_array_field(r, &["assumptions"])).unwrap_or_default(),
        },
        "attackerStories": attacker_stories,
        "criticalityBuckets": {
            "critical": criticality.map(|r| string_array_field(r, &["critical"])).unwrap_or_default(),
            "high": criticality.map(|r| string_array_field(r, &["high"])).unwrap_or_default(),
            "medium": criticality.map(|r| string_array_field(r, &["medium"])).unwrap_or_default(),
            "low": criticality.map(|r| string_array_field(r, &["low"])).unwrap_or_default(),
        },
        "outOfScope": out_of_scope,
    }))
}

fn normalize_document(mut value: Value, methodology: &str) -> Result<Value> {
    if value.get("document").is_some() {
        value = value
            .get("document")
            .cloned()
            .context("document wrapper was missing document")?;
    }
    let object = value
        .as_object_mut()
        .with_context(|| "ThreatModelDocument must be a JSON object")?;
    object
        .entry("version".to_string())
        .or_insert_with(|| json!("2.0"));
    object.insert("methodology".to_string(), json!(methodology));

    let mut dfd = object
        .remove("dfd")
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    normalize_dfd(&mut dfd);
    object.insert("dfd".to_string(), dfd);

    let threats = object
        .remove("threats")
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let threats_array = threats.as_array().cloned().unwrap_or_default();
    object.insert("threats".to_string(), Value::Array(threats_array.clone()));
    object.insert("summary".to_string(), build_summary(&threats_array));
    Ok(value)
}

fn normalize_dfd(dfd: &mut Value) {
    let Some(object) = dfd.as_object_mut() else {
        *dfd = json!({"nodes":[],"flows":[],"trustBoundaries":[]});
        return;
    };
    let nodes = object
        .remove("nodes")
        .or_else(|| object.remove("elements"))
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let nodes = nodes
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|node| {
            node.get("type")
                .and_then(Value::as_str)
                .is_none_or(|kind| normalize_dfd_type(kind) != "data-flow")
        })
        .collect::<Vec<_>>();
    let flows = object
        .remove("flows")
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let boundaries = object
        .remove("trustBoundaries")
        .or_else(|| object.remove("trust_boundaries"))
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    object.insert("nodes".to_string(), Value::Array(nodes));
    object.insert(
        "flows".to_string(),
        Value::Array(flows.as_array().cloned().unwrap_or_default()),
    );
    object.insert(
        "trustBoundaries".to_string(),
        Value::Array(boundaries.as_array().cloned().unwrap_or_default()),
    );
}

fn apply_methodology(mut document: Value, methodology: &str) -> Result<Value> {
    if let Some(object) = document.as_object_mut() {
        object.insert("methodology".to_string(), json!(methodology));
        if methodology == "dread" {
            let threats = object
                .get("threats")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            object.insert("riskScores".to_string(), build_dread_scores(&threats));
        } else {
            object.remove("riskScores");
        }
    }
    Ok(document)
}

fn build_summary(threats: &[Value]) -> Value {
    let mut by_severity = BTreeMap::<String, usize>::new();
    let mut by_category = BTreeMap::<String, usize>::new();
    for threat in threats {
        if let Some(impact) = threat.get("impact").and_then(Value::as_str) {
            *by_severity.entry(impact.to_string()).or_default() += 1;
        }
        if let Some(category) = threat.get("category").and_then(Value::as_str) {
            *by_category.entry(category.to_string()).or_default() += 1;
        }
    }
    json!({
        "total": threats.len(),
        "bySeverity": by_severity,
        "byCategory": by_category,
    })
}

fn build_dread_scores(threats: &[Value]) -> Value {
    let scores = threats
        .iter()
        .map(|threat| {
            let impact = threat
                .get("impact")
                .and_then(Value::as_str)
                .unwrap_or("medium");
            let likelihood = threat
                .get("likelihood")
                .and_then(Value::as_str)
                .unwrap_or("medium");
            let damage = impact_score(impact);
            let reproducibility = likelihood_score(likelihood);
            let exploitability = if array_len(threat.get("preconditions")) == 0 {
                8.0
            } else {
                6.0
            };
            let affected_users = if impact == "critical" {
                9.0
            } else if impact == "high" {
                7.0
            } else {
                4.0
            };
            let discoverability = if array_len(threat.get("evidenceAnchors")) > 0 {
                6.0
            } else {
                3.0
            };
            let score =
                ((damage + reproducibility + exploitability + affected_users + discoverability)
                    / 5.0
                    * 10.0)
                    .round()
                    / 10.0;
            json!({
                "threatId": threat.get("id").and_then(Value::as_str).unwrap_or("unknown"),
                "damage": damage,
                "reproducibility": reproducibility,
                "exploitability": exploitability,
                "affectedUsers": affected_users,
                "discoverability": discoverability,
                "score": score,
                "rating": dread_rating(score),
                "rationale": [
                    format!("Damage follows impact={impact}."),
                    format!("Reproducibility follows likelihood={likelihood}."),
                ],
            })
        })
        .collect::<Vec<_>>();
    json!({
        "methodology": "dread",
        "scale": "0-10",
        "threats": scores,
    })
}

fn build_findings_from_document(document: &Value) -> Vec<Value> {
    document
        .get("threats")
        .and_then(Value::as_array)
        .map(|threats| {
            threats
                .iter()
                .filter_map(|threat| {
                    let id = threat.get("id").and_then(Value::as_str)?;
                    let title = threat.get("title").and_then(Value::as_str).unwrap_or(id);
                    let category = threat
                        .get("category")
                        .and_then(Value::as_str)
                        .unwrap_or("threat");
                    let impact = threat
                        .get("impact")
                        .and_then(Value::as_str)
                        .unwrap_or("medium");
                    let affected = threat
                        .get("affectedFiles")
                        .and_then(Value::as_array)
                        .and_then(|items| items.first())
                        .and_then(Value::as_object);
                    Some(json!({
                        "ruleId": format!("threat-model/{category}"),
                        "filePath": affected
                            .and_then(|item| item.get("filePath"))
                            .and_then(Value::as_str)
                            .unwrap_or("threat-model"),
                        "startLine": affected
                            .and_then(|item| item.get("startLine"))
                            .and_then(Value::as_u64)
                            .unwrap_or(1),
                        "severity": impact.to_uppercase(),
                        "message": title,
                        "threatId": id,
                    }))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn extract_document_and_findings(raw: Value) -> Result<(Value, Option<Vec<Value>>)> {
    if let Some(object) = raw.as_object() {
        if let Some(document) = object.get("document") {
            let findings = object
                .get("findings")
                .and_then(Value::as_array)
                .map(|items| items.to_vec());
            return Ok((document.clone(), findings));
        }
    }
    Ok((raw, None))
}

fn parse_json_from_agent_text(text: &str) -> Result<Value> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        anyhow::bail!("pi-agent-core returned no threat model content");
    }
    let candidate = if let Some(stripped) = trimmed.strip_prefix("```") {
        stripped
            .trim_start_matches("json")
            .trim()
            .strip_suffix("```")
            .unwrap_or(stripped)
            .trim()
    } else {
        trimmed
    };
    match serde_json::from_str(candidate) {
        Ok(value) => Ok(value),
        Err(_) => {
            let start = candidate.find('{').context("no JSON object start found")?;
            let end = candidate.rfind('}').context("no JSON object end found")?;
            serde_json::from_str(&candidate[start..=end])
                .context("Could not parse JSON object from pi-agent-core response")
        }
    }
}

fn load_persistent_threat_model(root: &Path) -> Option<Value> {
    let path = root.join(".kuzushi").join("threat-model.json");
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn save_persistent_threat_model(root: &Path, document: &Value, force: bool) -> Result<bool> {
    let path = root.join(".kuzushi").join("threat-model.json");
    if !force && path.exists() {
        if let Some(existing) = read_json_optional(&path) {
            if existing
                .get("userEdited")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Ok(false);
            }
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(document)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(true)
}

fn write_normalized_artifact(root: &Path, output_dir: &str, document: &Value) -> Result<PathBuf> {
    let dir = resolve_output_dir(root, output_dir);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join("normalized-threat-model.json");
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(document)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

fn read_json_optional(path: &Path) -> Option<Value> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str::<Value>(&raw).ok()
}

fn resolve_output_dir(root: &Path, output_dir: &str) -> PathBuf {
    let path = PathBuf::from(output_dir);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(target) = read_string(input, &["target"]) {
        let candidate = PathBuf::from(target);
        let path = if candidate.is_absolute() {
            candidate
        } else {
            std::env::current_dir()
                .context("Could not resolve current directory")?
                .join(candidate)
        };
        return Ok(path);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    std::env::current_dir().context("Could not resolve current directory")
}

fn read_stages(input: &Value, tool_name: &str) -> Result<Vec<String>> {
    let Some(raw) = input.get("stages") else {
        return Ok(VALID_STAGES.iter().map(|stage| stage.to_string()).collect());
    };
    let Value::Array(items) = raw else {
        anyhow::bail!("{tool_name} stages must be an array of stage ids");
    };
    let mut stages = Vec::new();
    let mut unknown = Vec::new();
    for item in items {
        let Some(stage) = item
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            anyhow::bail!("{tool_name} stages entries must be strings");
        };
        if VALID_STAGES.contains(&stage) {
            stages.push(stage.to_string());
        } else {
            unknown.push(stage.to_string());
        }
    }
    if !unknown.is_empty() {
        anyhow::bail!(
            "{tool_name} unknown stage(s): {}. Valid: s1, s2, s3, s4.",
            unknown.join(", ")
        );
    }
    if stages.is_empty() {
        Ok(VALID_STAGES.iter().map(|stage| stage.to_string()).collect())
    } else {
        Ok(stages)
    }
}

fn read_methodology(input: &Value, fallback: &str) -> String {
    read_string(input, &["methodology", "type"])
        .map(|value| value.to_lowercase())
        .filter(|value| VALID_METHODOLOGIES.contains(&value.as_str()))
        .unwrap_or_else(|| fallback.to_string())
}

fn read_string(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

fn read_bool(input: &Value, keys: &[&str], fallback: bool) -> bool {
    keys.iter()
        .find_map(|key| input.get(*key).and_then(Value::as_bool))
        .unwrap_or(fallback)
}

fn read_usize(input: &Value, keys: &[&str], fallback: usize, min: usize) -> usize {
    let value = keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .or_else(|| {
                input
                    .get(*key)
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<usize>().ok())
            })
    });
    value.filter(|value| *value >= min).unwrap_or(fallback)
}

fn repo_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("repo")
        .to_string()
}

fn inventory_files(root: &Path, limit: usize) -> Result<Vec<String>> {
    let mut out = Vec::new();
    collect_inventory(root, root, limit, &mut out)?;
    if out.is_empty() {
        out.push("(no files found)".to_string());
    }
    Ok(out)
}

fn collect_inventory(root: &Path, dir: &Path, limit: usize, out: &mut Vec<String>) -> Result<()> {
    if out.len() >= limit {
        return Ok(());
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        if out.len() >= limit {
            break;
        }
        let name = entry.file_name();
        if should_skip_path(&name.to_string_lossy()) {
            continue;
        }
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_inventory(root, &path, limit, out)?;
        } else if file_type.is_file() {
            out.push(
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn read_manifest_summary(root: &Path) -> Result<String> {
    let mut lines = Vec::new();
    for name in ["package.json", "Cargo.toml", "pyproject.toml", "go.mod"] {
        let path = root.join(name);
        if !path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("Could not read manifest {}", path.display()))?;
        let snippet = raw
            .lines()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
            .chars()
            .take(2000)
            .collect::<String>();
        lines.push(format!("--- {name} ---\n{snippet}"));
    }
    if lines.is_empty() {
        Ok("(no recognized manifests)".to_string())
    } else {
        Ok(lines.join("\n\n"))
    }
}

fn should_skip_path(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".kuzushi"
            | ".next"
            | ".turbo"
            | "coverage"
            | "dist"
            | "native"
            | "node_modules"
            | "target"
    )
}

fn records(raw: Option<&Value>) -> Vec<&Map<String, Value>> {
    raw.and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

fn records_or_record_collections(raw: Option<&Value>) -> Vec<&Map<String, Value>> {
    match raw {
        Some(Value::Array(_)) => records(raw),
        Some(Value::Object(map)) => map
            .values()
            .flat_map(|value| records(Some(value)))
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    }
}

fn str_field(record: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        record
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

fn string_array_field(record: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| record.get(*key))
        .map(string_array)
        .unwrap_or_default()
}

fn string_array(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => vec![value.trim().to_string()],
        Value::Array(items) => items
            .iter()
            .filter_map(|item| match item {
                Value::String(value) => Some(value.trim().to_string()),
                Value::Number(value) => Some(value.to_string()),
                _ => None,
            })
            .filter(|value| !value.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn number_field(record: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        record
            .get(*key)
            .and_then(Value::as_u64)
            .or_else(|| {
                record
                    .get(*key)
                    .and_then(Value::as_i64)
                    .map(|value| value.max(1) as u64)
            })
            .or_else(|| {
                record
                    .get(*key)
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<u64>().ok())
            })
    })
}

fn nonempty_string_array(mut values: Vec<String>, fallback: &str) -> Vec<String> {
    if values.is_empty() {
        values.push(fallback.to_string());
    }
    values
}

fn actor_type_to_dfd_type(kind: &str) -> &'static str {
    match kind.to_lowercase().as_str() {
        "external-user" | "external-service" | "external" | "human" => "external-entity",
        "automated" | "downstream-service" | "internal-service" => "process",
        _ => "external-entity",
    }
}

fn component_kind_to_dfd_type(kind: &str) -> &'static str {
    let lower = kind.to_lowercase();
    if lower.contains("database") || lower.contains("store") {
        "data-store"
    } else if lower.contains("flow") {
        "data-flow"
    } else {
        "process"
    }
}

fn normalize_dfd_type(kind: &str) -> &'static str {
    match kind.to_lowercase().replace('_', "-").as_str() {
        "external-entity" | "external" => "external-entity",
        "data-store" | "datastore" => "data-store",
        "data-flow" | "dataflow" => "data-flow",
        _ => "process",
    }
}

fn normalize_stride_category(kind: &str) -> Option<&'static str> {
    let normalized = kind.to_lowercase().replace('_', "-");
    STRIDE_CATEGORIES
        .iter()
        .copied()
        .find(|category| *category == normalized)
}

fn normalize_impact(value: &str) -> &'static str {
    match value.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "low" => "low",
        _ => "medium",
    }
}

fn probability_to_likelihood(probability: f64) -> &'static str {
    if probability >= 0.7 {
        "high"
    } else if probability >= 0.4 {
        "medium"
    } else {
        "low"
    }
}

fn build_cwe_list(record: &Map<String, Value>) -> Vec<String> {
    let mut out = string_array_field(record, &["related_cwe", "relatedCwe", "cwe"]);
    if let Some(owasp) = str_field(record, &["owasp_category", "owasp"]) {
        out.push(format!("OWASP-{owasp}"));
    }
    if let Some(capec) = str_field(record, &["capec_id", "capecId"]) {
        out.push(capec);
    }
    out.sort();
    out.dedup();
    out
}

fn array_len(value: Option<&Value>) -> usize {
    value.and_then(Value::as_array).map(Vec::len).unwrap_or(0)
}

fn impact_score(impact: &str) -> f64 {
    match impact {
        "critical" => 10.0,
        "high" => 8.0,
        "low" => 2.0,
        _ => 5.0,
    }
}

fn likelihood_score(likelihood: &str) -> f64 {
    match likelihood {
        "high" => 8.0,
        "low" => 2.0,
        _ => 5.0,
    }
}

fn dread_rating(score: f64) -> &'static str {
    if score >= 8.5 {
        "critical"
    } else if score >= 6.5 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else {
        "low"
    }
}

fn methodology_label(methodology: &str) -> &'static str {
    match methodology {
        "stride" => "STRIDE",
        "dread" => "DREAD",
        _ => "PASTA",
    }
}

fn append_top_threats(lines: &mut Vec<String>, document: &Value) {
    let Some(threats) = document.get("threats").and_then(Value::as_array) else {
        return;
    };
    if threats.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("Top threats:".to_string());
    for threat in threats.iter().take(5) {
        let category = threat
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("threat");
        let title = threat
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("untitled");
        let impact = threat
            .get("impact")
            .and_then(Value::as_str)
            .unwrap_or("medium");
        lines.push(format!("  - [{category}] {title} (impact={impact})"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::config::V2Config;
    use crate::findings::{TriageOutcome, TriageVerdict};
    use crate::modules::{ModuleRegistry, ToolExecutionContext};
    use crate::runtime::{AgentQueryResponse, TriageRequest};
    use crate::workspace::WorkspaceTarget;

    #[test]
    fn parses_text_json_with_markdown_fence() {
        let parsed = parse_json_from_agent_text("```json\n{\"version\":\"2.0\"}\n```").unwrap();
        assert_eq!(parsed.get("version").and_then(Value::as_str), Some("2.0"));
    }

    struct MockThreatRuntime {
        requests: Mutex<Vec<AgentQueryRequest>>,
        response: Value,
    }

    impl MockThreatRuntime {
        fn new(response: Value) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                response,
            }
        }

        fn requests(&self) -> Vec<AgentQueryRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl AgentRuntime for MockThreatRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.requests.lock().unwrap().push(request);
            Ok(AgentQueryResponse {
                text: String::new(),
                structured: Some(self.response.clone()),
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            Ok(TriageOutcome {
                verdict: TriageVerdict::NeedsReview,
                confidence: 0.0,
                rationale: "unused".to_string(),
            })
        }
    }

    fn sample_document() -> Value {
        json!({
            "version": "2.0",
            "dfd": {
                "nodes": [
                    {
                        "id": "actor-user",
                        "type": "external-entity",
                        "name": "User",
                        "description": "External user",
                        "trustZone": "external"
                    },
                    {
                        "id": "web",
                        "type": "process",
                        "name": "Web App",
                        "description": "HTTP application",
                        "trustZone": "internal"
                    }
                ],
                "flows": [
                    {
                        "id": "flow-login",
                        "description": "Login request",
                        "sourceId": "actor-user",
                        "targetId": "web",
                        "trustBoundaryIds": ["tb-edge"]
                    }
                ],
                "trustBoundaries": [
                    {
                        "id": "tb-edge",
                        "name": "Internet edge",
                        "innerZone": "internal",
                        "outerZone": "external",
                        "crossingFlowIds": ["flow-login"]
                    }
                ]
            },
            "threats": [
                {
                    "id": "T-001",
                    "targetElementIds": ["web"],
                    "category": "spoofing",
                    "title": "Session spoofing",
                    "description": "Attacker spoofs a session",
                    "attackVector": "stolen token",
                    "preconditions": [],
                    "impact": "high",
                    "likelihood": "medium",
                    "existingMitigations": [],
                    "missingMitigations": ["Bind sessions"],
                    "relatedCwe": ["CWE-287"],
                    "affectedFiles": [{"filePath":"src/auth.ts","startLine":1}]
                }
            ],
            "summary": {
                "total": 1,
                "bySeverity": {"high": 1},
                "byCategory": {"spoofing": 1}
            }
        })
    }

    #[test]
    fn dispatches_threat_model_build_through_runtime_and_persists_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockThreatRuntime::new(json!({"document": sample_document()}));
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool_with_runtime(
                "threat-model:build",
                json!({
                    "outputDir": ".kuzushi/tm-artifacts",
                    "methodology": "dread",
                    "emitFindings": true,
                    "preserveUserEdits": false
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/document/methodology")
                .and_then(Value::as_str),
            Some("dread")
        );
        assert_eq!(
            result
                .pointer("/data/document/riskScores/methodology")
                .and_then(Value::as_str),
            Some("dread")
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/threatId")
                .and_then(Value::as_str),
            Some("T-001")
        );
        assert_eq!(
            result.pointer("/data/persisted").and_then(Value::as_bool),
            Some(true)
        );
        assert!(temp.path().join(".kuzushi/threat-model.json").exists());
        assert!(temp
            .path()
            .join(".kuzushi/tm-artifacts/normalized-threat-model.json")
            .exists());
        let requests = runtime.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].model, "openai:gpt-4.1");
        assert!(requests[0].prompt.contains("Repository inventory"));
    }

    #[test]
    fn threat_model_build_requires_runtime_and_explicit_model() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let err = registry
            .execute_tool("threat-model:build", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockThreatRuntime::new(json!({"document": sample_document()}));
        let err = registry
            .execute_tool_with_runtime("threat-model:build", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn reads_randori_pasta_artifacts_and_applies_methodology_overlay() {
        let temp = tempfile::tempdir().unwrap();
        let artifact_dir = temp.path().join(".kuzushi/runs/run-1/threat-model-output");
        fs::create_dir_all(&artifact_dir).unwrap();
        fs::write(
            artifact_dir.join("pasta-s2.json"),
            r#"{
              "actors": [{"id":"actor-user","name":"User","type":"external-user","description":"External user"}],
              "services": [{"id":"web","name":"Web App","description":"HTTP service"}],
              "data_flows": [{"id":"flow-login","source":"actor-user","destination":"web","data":"credentials","crosses":["tb-edge"]}]
            }"#,
        )
        .unwrap();
        fs::write(
            artifact_dir.join("pasta-s3.json"),
            r#"{
              "trust_boundaries": [{"id":"tb-edge","name":"Internet edge","crossing_flow_ids":["flow-login"]}]
            }"#,
        )
        .unwrap();
        fs::write(
            artifact_dir.join("pasta-s4.json"),
            r#"{
              "threats": [{
                "id": "T-001",
                "title": "Spoof login",
                "stride_category": "spoofing",
                "target_assets": ["web"],
                "probability": 0.8,
                "impact": "high",
                "attack_scenario": "Attacker steals a token",
                "recommended_mitigations": ["Bind sessions"],
                "evidence_anchors": [{"file_path":"src/auth.ts","start_line":7,"description":"login handler"}]
              }]
            }"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool(
                "threat-model:read",
                json!({
                    "outputDir": ".kuzushi/runs/run-1/threat-model-output",
                    "methodology": "dread"
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/document/dfd/nodes")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            result
                .pointer("/data/document/dfd/flows")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/document/threats/0/id")
                .and_then(Value::as_str),
            Some("T-001")
        );
        assert_eq!(
            result
                .pointer("/data/document/riskScores/methodology")
                .and_then(Value::as_str),
            Some("dread")
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("Loaded DREAD threat model")));
    }

    #[test]
    fn randori_threat_model_reads_same_artifact_adapter() {
        let temp = tempfile::tempdir().unwrap();
        let artifact_dir = temp.path().join("randori-output");
        fs::create_dir_all(&artifact_dir).unwrap();
        fs::write(
            artifact_dir.join("normalized-threat-model.json"),
            serde_json::to_string_pretty(&sample_document()).unwrap(),
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool(
                "randori:threat-model",
                json!({"outputDir": "randori-output"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/document/threats/0/title")
                .and_then(Value::as_str),
            Some("Session spoofing")
        );
    }

    #[test]
    fn threat_model_methodologies_is_static_and_headless() {
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
        };
        let result = registry
            .execute_tool("threat-model:methodologies", json!({}), &ctx)
            .unwrap();
        assert_eq!(
            result
                .pointer("/data/methodologies")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(3)
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("pasta")));
    }

    #[test]
    fn threat_model_dag_descriptors_remain_registered_for_scan_ordering() {
        let registry = ModuleRegistry::with_v2_builtins();
        let threat_model = registry
            .all_modules()
            .find(|module| module.metadata().id == "threat-model")
            .unwrap();
        assert!(threat_model.dag_nodes().iter().any(|node| {
            node.id == "threat-model:build"
                && node.output_kind == "threat-model"
                && node.depends_on == ["context:build"]
        }));

        let randori = registry
            .all_modules()
            .find(|module| module.metadata().id == "randori")
            .unwrap();
        assert!(randori
            .dag_nodes()
            .iter()
            .any(|node| node.id == "randori:threat-model" && node.output_kind == "threat-model"));
    }
}
