use super::*;

pub fn static_proof_claim_from_whitebox_schema(value: &Value) -> Result<StaticProofClaim> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("whitebox-static proof claim must be a JSON object"))?;
    let requested_state = read_object_string(object, &["staticProofState", "static_proof_state"])
        .map(|state| whitebox_static_proof_state_from_str(&state))
        .transpose()?
        .unwrap_or(StaticProofState::NeedsRuntimeEvidence);
    Ok(StaticProofClaim {
        requested_state,
        source_or_entrypoint_evidence: proof_evidence_from_object(
            object.get("source").and_then(Value::as_object),
            "source",
        ),
        sink_evidence: proof_evidence_from_object(
            object.get("sink").and_then(Value::as_object),
            "sink",
        ),
        path_explanation: read_nested_object_string(
            object,
            "path",
            &["explanation", "description"],
        )
        .or_else(|| read_object_string(object, &["pathExplanation", "path_explanation"])),
        local_direct_reason: read_nested_object_string(object, "path", &["localDirectReason"])
            .or_else(|| read_object_string(object, &["localDirectReason", "local_direct_reason"])),
        sanitizer_assessment: proof_assessment_from_object(
            object
                .get("sanitizerAssessment")
                .or_else(|| object.get("sanitizer_assessment"))
                .and_then(Value::as_object),
        ),
        guard_assessment: proof_assessment_from_object(
            object
                .get("guardAssessment")
                .or_else(|| object.get("guard_assessment"))
                .and_then(Value::as_object),
        ),
        citations: proof_citations_from_array(object.get("citations").and_then(Value::as_array)),
        assumptions: string_array(
            object
                .get("assumptions")
                .or_else(|| object.get("staticAssumptions")),
        ),
        missing_evidence: string_array(
            object
                .get("missingEvidence")
                .or_else(|| object.get("missing_evidence")),
        ),
    })
}

pub fn verify_static_proof_citation(
    repo_root: impl AsRef<Path>,
    citation: &StaticProofCitation,
) -> Result<VerifiedStaticProofCitation> {
    let span = extract_source_span(
        repo_root,
        &citation.file_path,
        citation.start_line,
        citation.end_line,
    )?;
    validate_citation_snippet(&span, citation)?;
    Ok(VerifiedStaticProofCitation {
        file_path: span.file_path,
        start_line: span.start_line,
        end_line: span.end_line,
        snippet_hash: span.content_hash,
    })
}

pub(crate) fn validate_confirmed_claim_shape(
    claim: &StaticProofClaim,
    verified_citations: &[VerifiedStaticProofCitation],
    issues: &mut Vec<String>,
) {
    if claim.source_or_entrypoint_evidence.is_empty() {
        issues.push("statically_confirmed requires source or entrypoint evidence".to_string());
    }
    if claim.sink_evidence.is_empty() {
        issues.push(
            "statically_confirmed requires sink or security-sensitive operation evidence"
                .to_string(),
        );
    }
    if !nonempty_option(&claim.path_explanation) && !nonempty_option(&claim.local_direct_reason) {
        issues.push(
            "statically_confirmed requires a path explanation or local/direct reason".to_string(),
        );
    }
    validate_assessment("sanitizer assessment", &claim.sanitizer_assessment, issues);
    validate_assessment("guard assessment", &claim.guard_assessment, issues);
    if verified_citations.is_empty() {
        issues
            .push("statically_confirmed requires at least one verified code citation".to_string());
    }
    if !has_nonempty(&claim.assumptions) {
        issues.push("statically_confirmed requires explicit assumptions".to_string());
    }
    if !has_nonempty(&claim.missing_evidence) {
        issues
            .push("statically_confirmed requires explicit missing evidence or limits".to_string());
    }
}

pub(crate) fn validate_assessment(
    label: &str,
    assessment: &StaticProofAssessment,
    issues: &mut Vec<String>,
) {
    if assessment.status == StaticProofAssessmentStatus::Unknown {
        issues.push(format!(
            "statically_confirmed requires known {label} status"
        ));
    }
    if assessment.explanation.trim().is_empty() {
        issues.push(format!("statically_confirmed requires {label} explanation"));
    }
}
