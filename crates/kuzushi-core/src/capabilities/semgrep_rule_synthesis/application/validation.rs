use crate::capabilities::semgrep_rule_synthesis::domain::{
    contains_any, regex_escape, tokens_present, SemgrepCandidateRule, SemgrepRuleFixture,
    SemgrepRuleValidation, GUARD_TOKENS,
};
use crate::evidence::static_evidence::StaticEvidenceNode;
use crate::findings::Finding;

pub(crate) fn validate_candidate(
    source_tokens: &[String],
    sink_tokens: &[String],
    fixtures: &[SemgrepRuleFixture],
) -> SemgrepRuleValidation {
    let mut validation = SemgrepRuleValidation::empty();
    for fixture in fixtures {
        let matched = candidate_matches_fixture(source_tokens, sink_tokens, &fixture.body);
        if fixture.should_match {
            validation.positive_fixtures += 1;
            if matched {
                validation.positive_matches += 1;
            } else {
                validation
                    .missing_positive_fixtures
                    .push(fixture.name.clone());
            }
        } else {
            validation.negative_fixtures += 1;
            if matched {
                validation.negative_matches += 1;
                validation
                    .unexpected_negative_matches
                    .push(fixture.name.clone());
            }
        }
    }
    validation.passed = validation.positive_fixtures > 0
        && validation.negative_fixtures > 0
        && validation.positive_matches == validation.positive_fixtures
        && validation.negative_matches == 0;
    validation
}

pub(crate) fn candidate_matches_fixture(
    source_tokens: &[String],
    sink_tokens: &[String],
    body: &str,
) -> bool {
    let lower = body.to_ascii_lowercase();
    tokens_present(&lower, source_tokens)
        && tokens_present(&lower, sink_tokens)
        && !contains_any(&lower, GUARD_TOKENS)
}

pub(crate) fn render_candidate_rule_yaml(candidate: &SemgrepCandidateRule) -> String {
    let source_regex = candidate
        .source_tokens
        .iter()
        .map(|token| regex_escape(token))
        .collect::<Vec<_>>()
        .join("|");
    let sink_regex = candidate
        .sink_tokens
        .iter()
        .map(|token| regex_escape(token))
        .collect::<Vec<_>>()
        .join("|");
    format!(
        "# Kuzushi whitebox-static candidate rule. Disabled by default.\n\
         # disabled: true\n\
         rules:\n\
         - id: {id}\n\
           languages: [{languages}]\n\
           severity: {severity}\n\
           message: {message:?}\n\
           metadata:\n\
             kuzushiWhiteboxCandidate: true\n\
             enabled: false\n\
             disabled: true\n\
             readyForManualEnable: {ready}\n\
             sourceFingerprint: {fingerprint:?}\n\
             sourceRuleId: {source_rule_id:?}\n\
             sourceLocation: {source_location:?}\n\
             validationPassed: {passed}\n\
           patterns:\n\
           - pattern-regex: '(?s)({source_regex}).*({sink_regex})|({sink_regex}).*({source_regex})'\n",
        id = candidate.id,
        languages = candidate.languages.join(", "),
        severity = candidate.severity,
        message = candidate.message,
        ready = candidate.ready_for_manual_enable,
        fingerprint = candidate.source_fingerprint,
        source_rule_id = candidate.source_rule_id,
        source_location = candidate.source_location,
        passed = candidate.validation.passed,
    )
}

pub(crate) fn rule_corpus(finding: &Finding, evidence_nodes: &[StaticEvidenceNode]) -> String {
    let mut parts = vec![
        finding.rule_id.as_str(),
        finding.title.as_str(),
        finding.message.as_str(),
        finding.file_path.as_str(),
    ];
    let metadata = evidence_nodes
        .iter()
        .map(|node| node.metadata.to_string())
        .collect::<Vec<_>>();
    for node in evidence_nodes {
        parts.push(node.title.as_str());
        parts.push(node.body.as_str());
        if let Some(source_path) = node.source_path.as_deref() {
            parts.push(source_path);
        }
    }
    for item in &metadata {
        parts.push(item.as_str());
    }
    parts.join("\n").to_ascii_lowercase()
}
