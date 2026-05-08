use super::prelude::*;
use super::*;

pub(crate) fn synthesize_candidate_for_finding(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
    fixtures: &[SemgrepRuleFixture],
) -> Option<SemgrepCandidateRule> {
    let corpus = rule_corpus(finding, evidence_nodes);
    let source_tokens = matching_tokens(&corpus, SOURCE_TOKENS);
    let sink_tokens = matching_tokens(&corpus, SINK_TOKENS);
    if source_tokens.is_empty() || sink_tokens.is_empty() {
        return None;
    }

    let source_location = format!("{}:{}", finding.file_path, finding.start_line);
    let id = format!(
        "{CANDIDATE_RULE_PREFIX}.{}",
        candidate_slug(&finding.rule_id, &finding.fingerprint)
    );
    let language = semgrep_language_for_path(&finding.file_path);
    let candidate_fixtures = fixtures_for_candidate(finding, evidence_nodes, fixtures);
    let validation = validate_candidate(&source_tokens, &sink_tokens, &candidate_fixtures);
    let ready_for_manual_enable = validation.passed;
    let disabled_reason = if ready_for_manual_enable {
        "validated candidate; disabled until an operator reviews and enables it".to_string()
    } else {
        "fixture validation failed or was incomplete; candidate remains disabled".to_string()
    };
    let mut candidate = SemgrepCandidateRule {
        id,
        source_fingerprint: finding.fingerprint.clone(),
        source_rule_id: finding.rule_id.clone(),
        source_location,
        languages: vec![language],
        severity: "WARNING".to_string(),
        message: format!(
            "Kuzushi candidate for {}: source reaches sink without the expected static guard",
            finding.rule_id
        ),
        source_tokens,
        sink_tokens,
        guard_tokens: GUARD_TOKENS
            .iter()
            .map(|token| (*token).to_string())
            .collect(),
        disabled: true,
        enabled: false,
        ready_for_manual_enable,
        disabled_reason,
        validation,
        rule_yaml: String::new(),
    };
    candidate.rule_yaml = render_candidate_rule_yaml(&candidate);
    Some(candidate)
}

pub(crate) fn fixtures_for_candidate(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
    explicit_fixtures: &[SemgrepRuleFixture],
) -> Vec<SemgrepRuleFixture> {
    let mut fixtures = explicit_fixtures
        .iter()
        .filter(|fixture| {
            fixture
                .source_fingerprint
                .as_deref()
                .is_none_or(|fingerprint| fingerprint == finding.fingerprint)
        })
        .cloned()
        .collect::<Vec<_>>();
    if !fixtures.is_empty() {
        fixtures.sort_by(|left, right| left.name.cmp(&right.name));
        return fixtures;
    }

    let positive_body = evidence_nodes
        .iter()
        .map(|node| node.body.trim())
        .find(|body| {
            let lower = body.to_ascii_lowercase();
            contains_any(&lower, SOURCE_TOKENS) && contains_any(&lower, SINK_TOKENS)
        })
        .or_else(|| {
            let lower = finding.message.to_ascii_lowercase();
            (contains_any(&lower, SOURCE_TOKENS) && contains_any(&lower, SINK_TOKENS))
                .then_some(finding.message.trim())
        });

    let Some(positive_body) = positive_body.filter(|body| !body.is_empty()) else {
        return fixtures;
    };
    fixtures.push(
        SemgrepRuleFixture::positive("confirmed-source-snippet", positive_body.to_string())
            .for_finding(finding.fingerprint.clone()),
    );
    fixtures.push(
        SemgrepRuleFixture::negative(
            "guarded-negative-snippet",
            guarded_negative_fixture(positive_body),
        )
        .for_finding(finding.fingerprint.clone()),
    );
    fixtures
}
