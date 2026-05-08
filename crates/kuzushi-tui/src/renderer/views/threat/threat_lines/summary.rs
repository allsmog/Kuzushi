use super::*;

pub(super) fn append_summary_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let doc = current_threat_model_doc(app);
    let review = ThreatReview::from_doc(doc.as_ref(), app.pending_threat_patch.as_ref());

    lines.push(section_header_line("THREAT MODEL REVIEW", area.width));
    append_review_summary(lines, &review);
    lines.push(blank());

    lines.push(section_header_line("SURFACE", area.width));
    append_surface_rows(lines, &review);
    lines.push(blank());

    lines.push(section_header_line(
        "ASSUMPTIONS / MISSING INPUTS",
        area.width,
    ));
    append_review_list(lines, "assumption", &review.assumptions);
    append_review_list(lines, "missing", &review.missing_inputs);
    lines.push(blank());

    lines.push(section_header_line("PROPOSED CHANGES", area.width));
    append_review_list(lines, "change", &review.proposed_changes);
    lines.push(blank());

    lines.push(section_header_line("ACTIONS", area.width));
    lines.push(detail("approve", "/threats apply"));
    lines.push(detail("regenerate", "/threats regen"));
    lines.push(detail("edit", "/threats edit"));
    lines.push(detail("export", ".kuzushi/threat-model.json"));
    lines.push(blank());

    lines.push(section_header_line("EVIDENCE / PROOF LIMITS", area.width));
    append_review_list(lines, "limit", &review.limitations);
}

struct ThreatReview {
    status: String,
    summary: String,
    threats: String,
    assets: String,
    actors: String,
    flows: String,
    trust_boundaries: String,
    assumptions: Vec<String>,
    missing_inputs: Vec<String>,
    proposed_changes: Vec<String>,
    limitations: Vec<String>,
}

impl ThreatReview {
    fn from_doc(doc: Option<&serde_json::Value>, patch: Option<&ThreatPatch>) -> Self {
        let Some(doc) = doc else {
            return Self::unknown(patch);
        };
        Self {
            status: "current persisted model".to_string(),
            summary: doc_summary(doc),
            threats: count_label(array_len(doc.get("threats")), "threat"),
            assets: count_label(node_count(doc), "asset"),
            actors: count_label(actor_count(doc), "actor"),
            flows: count_label(array_len(doc.pointer("/dfd/flows")), "data flow"),
            trust_boundaries: count_label(
                array_len(doc.pointer("/dfd/trustBoundaries")),
                "trust boundary",
            ),
            assumptions: string_list(doc, &["/assumptions", "/metadata/assumptions"]),
            missing_inputs: string_list(
                doc,
                &[
                    "/missingInputs",
                    "/missing_inputs",
                    "/metadata/missingInputs",
                ],
            ),
            proposed_changes: proposed_changes(patch),
            limitations: evidence_limitations(doc),
        }
    }

    fn unknown(patch: Option<&ThreatPatch>) -> Self {
        Self {
            status: "unknown".to_string(),
            summary: "unknown - no persisted threat model found".to_string(),
            threats: "unknown".to_string(),
            assets: "unknown".to_string(),
            actors: "unknown".to_string(),
            flows: "unknown".to_string(),
            trust_boundaries: "unknown".to_string(),
            assumptions: vec!["unknown - build or import a threat model first".to_string()],
            missing_inputs: vec!["unknown".to_string()],
            proposed_changes: proposed_changes(patch),
            limitations: vec![
                "unknown evidence coverage until a threat model artifact exists".to_string(),
            ],
        }
    }
}

fn append_review_summary(lines: &mut Vec<Line<'static>>, review: &ThreatReview) {
    lines.push(detail("status", &review.status));
    lines.push(detail("summary", &review.summary));
    lines.push(detail("threats", &review.threats));
}

fn append_surface_rows(lines: &mut Vec<Line<'static>>, review: &ThreatReview) {
    lines.push(detail("assets", &review.assets));
    lines.push(detail("actors", &review.actors));
    lines.push(detail("data flows", &review.flows));
    lines.push(detail("trust boundaries", &review.trust_boundaries));
}

fn append_review_list(lines: &mut Vec<Line<'static>>, label: &str, values: &[String]) {
    if values.is_empty() {
        lines.push(detail(label, "unknown"));
        return;
    }
    for value in values {
        lines.push(detail(label, value));
    }
}

fn doc_summary(doc: &serde_json::Value) -> String {
    doc.pointer("/summary/text")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            doc.pointer("/summary/description")
                .and_then(serde_json::Value::as_str)
        })
        .map(ToString::to_string)
        .unwrap_or_else(|| "current threat model loaded; narrative summary unknown".to_string())
}

fn node_count(doc: &serde_json::Value) -> Option<usize> {
    array_len(doc.pointer("/dfd/nodes"))
}

fn actor_count(doc: &serde_json::Value) -> Option<usize> {
    let nodes = doc.pointer("/dfd/nodes")?.as_array()?;
    Some(
        nodes
            .iter()
            .filter(|node| {
                node.get("type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|kind| kind == "external-entity" || kind == "actor")
            })
            .count(),
    )
}

fn array_len(value: Option<&serde_json::Value>) -> Option<usize> {
    value.and_then(serde_json::Value::as_array).map(Vec::len)
}

fn count_label(count: Option<usize>, singular: &str) -> String {
    match count {
        Some(1) => format!("1 {singular}"),
        Some(count) => format!("{count} {singular}s"),
        None => "unknown".to_string(),
    }
}

fn string_list(doc: &serde_json::Value, pointers: &[&str]) -> Vec<String> {
    pointers
        .iter()
        .find_map(|pointer| doc.pointer(pointer).and_then(serde_json::Value::as_array))
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn proposed_changes(patch: Option<&ThreatPatch>) -> Vec<String> {
    match patch {
        Some(patch) => {
            let mut changes = vec![patch.summary.clone()];
            changes.extend(
                patch
                    .unsupported
                    .iter()
                    .map(|note| format!("unsupported: {note}")),
            );
            changes
        }
        None => vec!["none pending".to_string()],
    }
}

fn evidence_limitations(doc: &serde_json::Value) -> Vec<String> {
    let anchors = array_len(doc.pointer("/evidenceAnchors"))
        .or_else(|| array_len(doc.pointer("/evidence/anchors")));
    let mut limits = vec![
        "threat model is review context, not exploit proof".to_string(),
        "downstream findings still require source evidence and verification".to_string(),
    ];
    if anchors.unwrap_or(0) == 0 {
        limits.push("evidence anchors unknown".to_string());
    }
    limits
}
