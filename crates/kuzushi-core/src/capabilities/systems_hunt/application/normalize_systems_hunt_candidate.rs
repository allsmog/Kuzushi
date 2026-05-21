use super::*;

pub(super) struct SystemsHuntCandidate<'a> {
    pub(super) object: &'a serde_json::Map<String, Value>,
    title: String,
    file_path: String,
    message: String,
    start_line: u32,
    severity: Severity,
    evidence: Vec<String>,
    attacker_inputs: Vec<String>,
    hardening_notes: Vec<String>,
    impact: Option<String>,
    function: Option<String>,
    domain: Vec<String>,
    reasoning: Option<String>,
    cwe_list: Vec<String>,
    violated_invariant_ids: Vec<String>,
    violated_invariant: String,
    trigger_hypothesis_ids: Vec<String>,
    trigger_sequence: Vec<String>,
    cheap_verifiable: bool,
    corroboration_status: String,
}

impl SystemsHuntCandidate<'_> {
    fn cwe_rule_segment(&self) -> String {
        self.cwe_list
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub(super) fn is_under_evidenced(&self) -> bool {
        is_under_evidenced_systems_hunt_candidate(
            &self.evidence,
            &self.violated_invariant_ids,
            &self.violated_invariant,
            &self.trigger_hypothesis_ids,
            &self.trigger_sequence,
            self.cheap_verifiable,
            &self.corroboration_status,
        )
    }
}

pub(super) fn parse_systems_hunt_candidate(item: &Value) -> Option<SystemsHuntCandidate<'_>> {
    let object = item.as_object()?;
    let title = first_string_field(object, &["title", "name"]);
    let file_path = normalize_candidate_path(object);
    let message = collect_finding_body(object, &title);
    if title.is_empty() || file_path.is_empty() || message.is_empty() {
        return None;
    }

    Some(SystemsHuntCandidate {
        object,
        title,
        file_path,
        message,
        start_line: candidate_start_line(object),
        severity: parse_severity(string_field(object.get("severity"))),
        evidence: candidate_evidence(object),
        attacker_inputs: candidate_attacker_inputs(object),
        hardening_notes: candidate_hardening_notes(object),
        impact: candidate_impact(object),
        function: candidate_function(object),
        domain: first_string_array_field(object, &["domains", "domain"]),
        reasoning: optional_string(first_string_field(object, &["reasoning", "rationale"])),
        cwe_list: first_string_array_field(object, &["cwe", "cwes"]),
        violated_invariant_ids: string_array(object.get("violatedInvariantIds")),
        violated_invariant: string_field(object.get("violatedInvariant")),
        trigger_hypothesis_ids: string_array(object.get("triggerHypothesisIds")),
        trigger_sequence: string_array(object.get("triggerSequence")),
        cheap_verifiable: object
            .get("cheapVerifiable")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        corroboration_status: string_field(object.get("corroborationStatus")),
    })
}

fn normalize_candidate_path(object: &serde_json::Map<String, Value>) -> String {
    normalize_relative_path(first_string_field(
        object,
        &["filePath", "file_path", "path", "file"],
    ))
}

fn candidate_start_line(object: &serde_json::Map<String, Value>) -> u32 {
    first_line_field(
        object,
        &[
            "startLine",
            "start_line",
            "line",
            "lines",
            "anchorLine",
            "line_start",
            "lineStart",
            "anchorLines",
            "lineRange",
            "line_range",
        ],
    )
    .max(1) as u32
}

fn candidate_evidence(object: &serde_json::Map<String, Value>) -> Vec<String> {
    first_string_array_field(
        object,
        &["evidence", "evidenceAnchors", "supporting_evidence"],
    )
}

fn candidate_attacker_inputs(object: &serde_json::Map<String, Value>) -> Vec<String> {
    first_string_array_field(
        object,
        &[
            "attackerControlledFields",
            "attackerInputs",
            "attacker_inputs",
            "attacker_input",
        ],
    )
}

fn candidate_hardening_notes(object: &serde_json::Map<String, Value>) -> Vec<String> {
    first_string_array_field(
        object,
        &[
            "hardeningNotes",
            "missingHardening",
            "missing_hardening",
            "recommendation",
            "recommendations",
            "fix",
        ],
    )
}

fn candidate_impact(object: &serde_json::Map<String, Value>) -> Option<String> {
    optional_string(first_string_field(
        object,
        &[
            "impact",
            "exploitability",
            "exploitability_notes",
            "exploitabilityNotes",
        ],
    ))
}

fn candidate_function(object: &serde_json::Map<String, Value>) -> Option<String> {
    optional_string(first_string_field(
        object,
        &["function", "functionName", "fn"],
    ))
}

pub(super) fn build_systems_hunt_finding(candidate: &SystemsHuntCandidate<'_>) -> Finding {
    let rule_id = candidate
        .object
        .get("ruleId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            format!(
                "systems-hunt/{}",
                sanitize_rule_segment(&candidate.cwe_rule_segment())
            )
        });
    let mut finding = Finding::new_tool(
        "systems-hunt",
        rule_id,
        candidate.file_path.clone(),
        candidate.start_line,
        None,
        candidate.severity,
        build_candidate_message(candidate),
    );
    finding.title = candidate.title.clone();
    finding
}

fn build_candidate_message(candidate: &SystemsHuntCandidate<'_>) -> String {
    build_finding_message(
        &candidate.title,
        &candidate.message,
        candidate.function.as_deref(),
        &candidate.evidence,
        candidate.impact.as_deref(),
        &candidate.hardening_notes,
        candidate.reasoning.as_deref(),
    )
}

pub(super) fn build_systems_hunt_artifact(
    candidate: &SystemsHuntCandidate<'_>,
    context: &SystemsContextOutput,
    finding: &Finding,
) -> Value {
    let surface = matching_surface(context, &candidate.file_path);
    json!({
        "fingerprint": finding.fingerprint,
        "title": finding.title,
        "cwe": candidate.cwe_list,
        "severity": candidate.severity.as_str(),
        "filePath": candidate.file_path,
        "startLine": candidate.start_line,
        "function": candidate.function,
        "domain": candidate.domain,
        "description": candidate.message,
        "evidence": candidate.evidence,
        "impact": candidate.impact,
        "recommendation": candidate.hardening_notes,
        "surfaceId": surface.map(|surface| surface.id.clone()).unwrap_or_default(),
        "surfaceKind": surface_kind(surface),
        "lenses": string_array(candidate.object.get("lenses")),
        "violatedInvariantIds": candidate.violated_invariant_ids,
        "violatedInvariant": candidate.violated_invariant,
        "triggerHypothesisIds": candidate.trigger_hypothesis_ids,
        "triggerSequence": candidate.trigger_sequence,
        "stateMachine": string_array(candidate.object.get("stateMachine")),
        "boundaryAssignments": candidate.object.get("boundaryAssignments").cloned().unwrap_or_else(|| json!({})),
        "attackerControlledFields": candidate.attacker_inputs,
        "memoryPrimitive": string_field(candidate.object.get("memoryPrimitive")),
        "hardeningNotes": candidate.hardening_notes,
        "cheapVerifiable": candidate.cheap_verifiable,
        "reasoning": candidate.reasoning,
        "analysisPath": candidate.object.get("analysisPath").cloned().unwrap_or_else(|| json!([])),
        "guardLocations": candidate.object.get("guardLocations").cloned().unwrap_or_else(|| json!([])),
        "counterexampleNotes": string_array(candidate.object.get("counterexampleNotes")),
        "relatedFiles": surface.map(|surface| vec![surface.file_path.clone()]).unwrap_or_default(),
        "corroborationStatus": candidate.corroboration_status,
    })
}

fn matching_surface<'a>(
    context: &'a SystemsContextOutput,
    file_path: &str,
) -> Option<&'a RankedSystemsSurface> {
    context
        .surfaces
        .iter()
        .find(|surface| surface.file_path == file_path)
        .or_else(|| context.surfaces.first())
}

fn surface_kind(surface: Option<&RankedSystemsSurface>) -> String {
    surface
        .map(|surface| surface.kind.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn attach_artifact_path(finding: &mut Finding, relative_artifact: &str) {
    finding.message = finding.message.replace(
        "Systems hunt artifact: pending",
        &format!("Systems hunt artifact: {relative_artifact}"),
    );
}

fn is_under_evidenced_systems_hunt_candidate(
    evidence: &[String],
    violated_invariant_ids: &[String],
    violated_invariant: &str,
    trigger_hypothesis_ids: &[String],
    trigger_sequence: &[String],
    cheap_verifiable: bool,
    corroboration_status: &str,
) -> bool {
    if cheap_verifiable || is_positive_corroboration_status(corroboration_status) {
        return false;
    }

    evidence.is_empty()
        && violated_invariant_ids.is_empty()
        && violated_invariant.trim().is_empty()
        && trigger_hypothesis_ids.is_empty()
        && trigger_sequence.is_empty()
}

fn is_positive_corroboration_status(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "confirmed" | "corroborated" | "code-cited" | "code_cited"
    )
}
