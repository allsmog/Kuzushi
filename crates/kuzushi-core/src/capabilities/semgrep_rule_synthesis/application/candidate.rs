use super::validate_candidate;
use super::validation::{render_candidate_rule_yaml, rule_corpus};
use crate::capabilities::semgrep_rule_synthesis::domain::{
    candidate_slug, contains_any, guarded_negative_fixture, matching_tokens,
    semgrep_language_for_path, SemgrepCandidateRule, SemgrepRuleFixture, CANDIDATE_RULE_PREFIX,
    GUARD_TOKENS, SINK_TOKENS, SOURCE_TOKENS, SemgrepRuleValidation,
};
use crate::evidence::static_evidence::StaticEvidenceNode;
use crate::findings::Finding;

pub(crate) fn synthesize_candidate_for_finding(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
    fixtures: &[SemgrepRuleFixture],
) -> Option<SemgrepCandidateRule> {
    let (source_tokens, sink_tokens) = candidate_tokens(finding, evidence_nodes)?;
    let candidate_fixtures = fixtures_for_candidate(finding, evidence_nodes, fixtures);
    let validation = validate_candidate(&source_tokens, &sink_tokens, &candidate_fixtures);
    let mut candidate = candidate_rule(finding, source_tokens, sink_tokens, validation);
    candidate.rule_yaml = render_candidate_rule_yaml(&candidate);
    Some(candidate)
}

fn candidate_tokens(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
) -> Option<(Vec<String>, Vec<String>)> {
    let corpus = rule_corpus(finding, evidence_nodes);
    let source_tokens = matching_tokens(&corpus, SOURCE_TOKENS);
    let sink_tokens = matching_tokens(&corpus, SINK_TOKENS);
    (!source_tokens.is_empty() && !sink_tokens.is_empty()).then_some((source_tokens, sink_tokens))
}

fn candidate_rule(
    finding: &Finding,
    source_tokens: Vec<String>,
    sink_tokens: Vec<String>,
    validation: SemgrepRuleValidation,
) -> SemgrepCandidateRule {
    let ready_for_manual_enable = validation.passed;
    SemgrepCandidateRule {
        id: candidate_rule_id(finding),
        source_fingerprint: finding.fingerprint.clone(),
        source_rule_id: finding.rule_id.clone(),
        source_location: format!("{}:{}", finding.file_path, finding.start_line),
        languages: vec![semgrep_language_for_path(&finding.file_path)],
        severity: "WARNING".to_string(),
        message: candidate_message(finding),
        source_tokens,
        sink_tokens,
        guard_tokens: GUARD_TOKENS.iter().map(|token| (*token).to_string()).collect(),
        disabled: true,
        enabled: false,
        ready_for_manual_enable,
        disabled_reason: candidate_disabled_reason(ready_for_manual_enable),
        validation,
        rule_yaml: String::new(),
    }
}

fn candidate_rule_id(finding: &Finding) -> String {
    format!(
        "{CANDIDATE_RULE_PREFIX}.{}",
        candidate_slug(&finding.rule_id, &finding.fingerprint)
    )
}

fn candidate_message(finding: &Finding) -> String {
    format!(
        "Kuzushi candidate for {}: source reaches sink without the expected static guard",
        finding.rule_id
    )
}

fn candidate_disabled_reason(ready_for_manual_enable: bool) -> String {
    if ready_for_manual_enable {
        "fixture-checked candidate; disabled until an operator reviews and enables it".to_string()
    } else {
        "fixture validation failed or was incomplete; candidate remains disabled".to_string()
    }
}

pub(crate) fn fixtures_for_candidate(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
    explicit_fixtures: &[SemgrepRuleFixture],
) -> Vec<SemgrepRuleFixture> {
    let mut fixtures = explicit_fixtures_for_candidate(finding, explicit_fixtures);
    if !fixtures.is_empty() {
        return fixtures;
    }

    let Some(positive_body) = positive_fixture_body(finding, evidence_nodes) else {
        return fixtures;
    };
    append_default_fixtures(&mut fixtures, finding, positive_body);
    fixtures
}

fn explicit_fixtures_for_candidate(
    finding: &Finding,
    explicit_fixtures: &[SemgrepRuleFixture],
) -> Vec<SemgrepRuleFixture> {
    let mut fixtures = explicit_fixtures
        .iter()
        .filter(|fixture| fixture_matches_finding(fixture, finding))
        .cloned()
        .collect::<Vec<_>>();
    fixtures.sort_by(|left, right| left.name.cmp(&right.name));
    fixtures
}

fn fixture_matches_finding(fixture: &SemgrepRuleFixture, finding: &Finding) -> bool {
    fixture
        .source_fingerprint
        .as_deref()
        .is_none_or(|fingerprint| fingerprint == finding.fingerprint)
}

fn positive_fixture_body<'a>(
    finding: &'a Finding,
    evidence_nodes: &'a [StaticEvidenceNode],
) -> Option<&'a str> {
    evidence_nodes
        .iter()
        .map(|node| node.body.trim())
        .find(|body| has_source_and_sink(body))
        .or_else(|| has_source_and_sink(&finding.message).then_some(finding.message.trim()))
        .filter(|body| !body.is_empty())
}

fn has_source_and_sink(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    contains_any(&lower, SOURCE_TOKENS) && contains_any(&lower, SINK_TOKENS)
}

fn append_default_fixtures(
    fixtures: &mut Vec<SemgrepRuleFixture>,
    finding: &Finding,
    positive_body: &str,
) {
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
}
