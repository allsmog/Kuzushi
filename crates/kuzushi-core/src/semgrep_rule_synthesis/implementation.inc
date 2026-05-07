use std::collections::BTreeSet;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::findings::{Finding, StaticProofState};
use crate::static_evidence::{StaticEvidenceNode, StaticEvidenceStore};

const CANDIDATE_RULE_PREFIX: &str = "kuzushi.whitebox.candidate";

const SOURCE_TOKENS: &[&str] = &[
    "req.query",
    "req.body",
    "req.params",
    "req.headers",
    "request.args",
    "request.form",
    "request.json",
    "process.argv",
    "argv",
    "urlsearchparams",
    "input",
];

const SINK_TOKENS: &[&str] = &[
    "db.query",
    ".query(",
    "execute(",
    "exec(",
    "spawn(",
    "eval(",
    "res.send",
    "innerhtml",
    "deserialize",
    "render(",
];

const GUARD_TOKENS: &[&str] = &[
    "sanitize",
    "sanitise",
    "escape",
    "validate",
    "validator",
    "allowlist",
    "allow_list",
    "parameterized",
    "parametrize",
    "prepare(",
    "preparedstatement",
    "dompurify",
    "zod",
    "joi",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepRuleSynthesisReport {
    pub count: usize,
    pub validation_passed: usize,
    pub candidates: Vec<SemgrepCandidateRule>,
    pub deterministic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepCandidateRule {
    pub id: String,
    pub source_fingerprint: String,
    pub source_rule_id: String,
    pub source_location: String,
    pub languages: Vec<String>,
    pub severity: String,
    pub message: String,
    pub source_tokens: Vec<String>,
    pub sink_tokens: Vec<String>,
    pub guard_tokens: Vec<String>,
    pub disabled: bool,
    pub enabled: bool,
    pub ready_for_manual_enable: bool,
    pub disabled_reason: String,
    pub validation: SemgrepRuleValidation,
    pub rule_yaml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepRuleValidation {
    pub passed: bool,
    pub positive_fixtures: usize,
    pub positive_matches: usize,
    pub negative_fixtures: usize,
    pub negative_matches: usize,
    pub missing_positive_fixtures: Vec<String>,
    pub unexpected_negative_matches: Vec<String>,
}

impl SemgrepRuleValidation {
    fn empty() -> Self {
        Self {
            passed: false,
            positive_fixtures: 0,
            positive_matches: 0,
            negative_fixtures: 0,
            negative_matches: 0,
            missing_positive_fixtures: Vec::new(),
            unexpected_negative_matches: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepRuleFixture {
    pub name: String,
    pub body: String,
    pub should_match: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_fingerprint: Option<String>,
}

impl SemgrepRuleFixture {
    pub fn positive(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
            should_match: true,
            source_fingerprint: None,
        }
    }

    pub fn negative(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
            should_match: false,
            source_fingerprint: None,
        }
    }

    pub fn for_finding(mut self, fingerprint: impl Into<String>) -> Self {
        self.source_fingerprint = Some(fingerprint.into());
        self
    }
}

pub fn synthesize_candidate_semgrep_rules(
    findings: &[Finding],
    evidence_store: Option<&StaticEvidenceStore>,
    fixtures: &[SemgrepRuleFixture],
) -> Result<SemgrepRuleSynthesisReport> {
    let mut candidates = Vec::new();
    for finding in findings
        .iter()
        .filter(|finding| finding.static_proof_state == Some(StaticProofState::StaticallyConfirmed))
    {
        let evidence_nodes = match evidence_store {
            Some(store) => store.list_nodes_for_finding(&finding.fingerprint)?,
            None => Vec::new(),
        };
        let Some(candidate) = synthesize_candidate_for_finding(finding, &evidence_nodes, fixtures)
        else {
            continue;
        };
        candidates.push(candidate);
    }
    candidates.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.source_location.cmp(&right.source_location))
            .then_with(|| left.source_fingerprint.cmp(&right.source_fingerprint))
    });
    let validation_passed = candidates
        .iter()
        .filter(|candidate| candidate.validation.passed)
        .count();
    Ok(SemgrepRuleSynthesisReport {
        count: candidates.len(),
        validation_passed,
        candidates,
        deterministic: true,
    })
}

fn synthesize_candidate_for_finding(
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

fn fixtures_for_candidate(
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

fn validate_candidate(
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

fn candidate_matches_fixture(source_tokens: &[String], sink_tokens: &[String], body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    tokens_present(&lower, source_tokens)
        && tokens_present(&lower, sink_tokens)
        && !contains_any(&lower, GUARD_TOKENS)
}

fn render_candidate_rule_yaml(candidate: &SemgrepCandidateRule) -> String {
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

fn rule_corpus(finding: &Finding, evidence_nodes: &[StaticEvidenceNode]) -> String {
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

fn matching_tokens(corpus: &str, candidates: &[&str]) -> Vec<String> {
    candidates
        .iter()
        .filter(|token| corpus.contains(&token.to_ascii_lowercase()))
        .map(|token| (*token).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn tokens_present(corpus: &str, tokens: &[String]) -> bool {
    tokens
        .iter()
        .any(|token| corpus.contains(&token.to_ascii_lowercase()))
}

fn contains_any(corpus: &str, tokens: &[&str]) -> bool {
    tokens
        .iter()
        .any(|token| corpus.contains(&token.to_ascii_lowercase()))
}

fn guarded_negative_fixture(positive_body: &str) -> String {
    format!(
        "const kuzushiCandidateValue = sanitize(req.query.kuzushi);\n{}\n",
        positive_body
    )
}

fn semgrep_language_for_path(path: &str) -> String {
    match path.rsplit('.').next().unwrap_or_default() {
        "js" | "jsx" | "mjs" | "cjs" => "javascript",
        "ts" | "tsx" => "typescript",
        "py" => "python",
        "go" => "go",
        "rs" => "rust",
        "java" => "java",
        "kt" => "kotlin",
        "rb" => "ruby",
        "php" => "php",
        "c" | "h" => "c",
        "cc" | "cpp" | "hpp" => "cpp",
        _ => "generic",
    }
    .to_string()
}

fn candidate_slug(rule_id: &str, fingerprint: &str) -> String {
    let mut slug = rule_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '.'
            }
        })
        .collect::<String>();
    while slug.contains("..") {
        slug = slug.replace("..", ".");
    }
    let slug = slug.trim_matches('.');
    let suffix = fingerprint.chars().take(8).collect::<String>();
    if slug.is_empty() {
        suffix
    } else {
        format!("{slug}.{suffix}")
    }
}

fn regex_escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        if matches!(
            ch,
            '.' | '+' | '*' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        ) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Severity, StaticProofState};
    use crate::static_evidence::{StaticEvidenceNode, StaticEvidenceNodeKind};

    #[test]
    fn semgrep_rule_synthesis_validates_disabled_candidate_from_confirmed_finding() {
        let finding = Finding::new_tool(
            "agentic-sast",
            "js/sql-injection",
            "src/users.ts",
            3,
            Some(3),
            Severity::High,
            "req.query reaches db.query without sanitizer",
        )
        .with_static_proof_state(StaticProofState::StaticallyConfirmed);
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        store
            .upsert_node(
                &StaticEvidenceNode::new(
                    StaticEvidenceNodeKind::CodeSpan,
                    "confirmed SQL flow",
                    "const q = req.query.q;\nreturn db.query(`select * from users where name = ${q}`);",
                )
                .with_finding_fingerprint(finding.fingerprint.clone())
                .with_source_span("src/users.ts", 2, Some(3)),
            )
            .unwrap();
        let fixtures = vec![
            SemgrepRuleFixture::positive(
                "positive",
                "const q = req.query.q;\nreturn db.query(`select * from users where name = ${q}`);",
            )
            .for_finding(finding.fingerprint.clone()),
            SemgrepRuleFixture::negative(
                "negative",
                "const q = sanitize(req.query.q);\nreturn db.query(`select * from users where name = ${q}`);",
            )
            .for_finding(finding.fingerprint.clone()),
        ];

        let report =
            synthesize_candidate_semgrep_rules(&[finding], Some(&store), &fixtures).unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.validation_passed, 1);
        let candidate = &report.candidates[0];
        assert!(candidate.validation.passed);
        assert!(candidate.ready_for_manual_enable);
        assert!(candidate.disabled);
        assert!(!candidate.enabled);
        assert!(candidate.rule_yaml.contains("disabled: true"));
        assert!(candidate.rule_yaml.contains("enabled: false"));
        assert!(candidate
            .rule_yaml
            .contains("kuzushiWhiteboxCandidate: true"));
        assert!(candidate.rule_yaml.contains("validationPassed: true"));
    }

    #[test]
    fn semgrep_rule_synthesis_ignores_non_confirmed_findings() {
        let unconfirmed = Finding::new_tool(
            "agentic-sast",
            "js/sql-injection",
            "src/users.ts",
            3,
            Some(3),
            Severity::High,
            "req.query reaches db.query",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);

        let report = synthesize_candidate_semgrep_rules(&[unconfirmed], None, &[]).unwrap();

        assert_eq!(report.count, 0);
        assert!(report.candidates.is_empty());
    }

    #[test]
    fn semgrep_rule_synthesis_keeps_failed_fixture_candidate_disabled() {
        let finding = Finding::new_tool(
            "agentic-sast",
            "js/command-injection",
            "src/admin.ts",
            5,
            Some(5),
            Severity::High,
            "req.body reaches exec(cmd) without validation",
        )
        .with_static_proof_state(StaticProofState::StaticallyConfirmed);
        let fixtures = vec![
            SemgrepRuleFixture::positive("positive", "const cmd = req.body.cmd;\nexec(cmd);")
                .for_finding(finding.fingerprint.clone()),
            SemgrepRuleFixture::negative(
                "negative-still-unsafe",
                "const cmd = req.body.cmd;\nexec(cmd);",
            )
            .for_finding(finding.fingerprint.clone()),
        ];

        let report = synthesize_candidate_semgrep_rules(&[finding], None, &fixtures).unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.validation_passed, 0);
        let candidate = &report.candidates[0];
        assert!(!candidate.validation.passed);
        assert!(!candidate.ready_for_manual_enable);
        assert!(candidate.disabled);
        assert!(!candidate.enabled);
        assert_eq!(
            candidate.validation.unexpected_negative_matches,
            vec!["negative-still-unsafe".to_string()]
        );
        assert!(candidate.rule_yaml.contains("validationPassed: false"));
    }

    #[test]
    fn semgrep_language_for_path_covers_supported_extensions() {
        let cases = [
            ("app.js", "javascript"),
            ("component.tsx", "typescript"),
            ("worker.py", "python"),
            ("main.go", "go"),
            ("lib.rs", "rust"),
            ("Service.java", "java"),
            ("Handler.kt", "kotlin"),
            ("job.rb", "ruby"),
            ("index.php", "php"),
            ("native.c", "c"),
            ("header.hpp", "cpp"),
            ("Dockerfile", "generic"),
        ];
        for (path, language) in cases {
            assert_eq!(semgrep_language_for_path(path), language);
        }
    }
}
