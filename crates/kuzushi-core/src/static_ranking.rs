use std::cmp::Ordering;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::attack_surface::{AttackSurface, AttackSurfaceKind, AttackSurfaceMap};
use crate::findings::{Finding, Severity, StaticProofState, TriageVerdict};
use crate::static_evidence::{StaticEvidenceNode, StaticEvidenceNodeKind, StaticEvidenceStore};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticRankedFinding {
    pub rank: usize,
    pub fingerprint: String,
    pub rule_id: String,
    pub title: String,
    pub tool: String,
    pub file_path: String,
    pub start_line: u32,
    pub severity: String,
    pub static_proof_state: Option<String>,
    pub impact: StaticImpactScore,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticImpactScore {
    pub total: i32,
    pub factors: StaticImpactFactors,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticImpactFactors {
    pub severity: i32,
    pub static_proof: i32,
    pub attack_surface_reachability: i32,
    pub source_sink_class: i32,
    pub data_sensitivity: i32,
    pub privilege_boundary: i32,
    pub sanitizer_absence: i32,
    pub framework_context: i32,
    pub codeql_flow_quality: i32,
    pub confidence: i32,
    pub noise_adjustment: i32,
}

pub fn rank_static_findings(
    findings: &[Finding],
    attack_surface: Option<&AttackSurfaceMap>,
    evidence_store: Option<&StaticEvidenceStore>,
) -> Result<Vec<StaticRankedFinding>> {
    let mut ranked = Vec::new();
    for finding in findings {
        let evidence_nodes = match evidence_store {
            Some(store) => store.list_nodes_for_finding(&finding.fingerprint)?,
            None => Vec::new(),
        };
        ranked.push(StaticRankedFinding {
            rank: 0,
            fingerprint: finding.fingerprint.clone(),
            rule_id: finding.rule_id.clone(),
            title: finding.title.clone(),
            tool: finding.tool.clone(),
            file_path: finding.file_path.clone(),
            start_line: finding.start_line,
            severity: finding.severity.as_str().to_string(),
            static_proof_state: finding
                .static_proof_state
                .map(|state| state.as_str().to_string()),
            impact: score_static_finding(finding, attack_surface, &evidence_nodes),
        });
    }

    ranked.sort_by(compare_ranked_findings);
    for (index, finding) in ranked.iter_mut().enumerate() {
        finding.rank = index + 1;
    }
    Ok(ranked)
}

pub fn score_static_finding(
    finding: &Finding,
    attack_surface: Option<&AttackSurfaceMap>,
    evidence_nodes: &[StaticEvidenceNode],
) -> StaticImpactScore {
    let mut factors = StaticImpactFactors::default();
    let mut reasons = Vec::new();
    let corpus = finding_corpus(finding, evidence_nodes);

    factors.severity = severity_score(finding.severity);
    if factors.severity > 0 {
        reasons.push(format!("severity={}", finding.severity.as_str()));
    }

    factors.static_proof = static_proof_score(finding.static_proof_state);
    if let Some(state) = finding.static_proof_state {
        reasons.push(format!("static_proof_state={}", state.as_str()));
    }

    factors.attack_surface_reachability =
        attack_surface_score(finding, attack_surface, evidence_nodes, &mut reasons);
    factors.source_sink_class = source_sink_score(&corpus, &mut reasons);
    factors.data_sensitivity = data_sensitivity_score(&corpus, &mut reasons);
    factors.privilege_boundary =
        privilege_boundary_score(&corpus, attack_surface, finding, &mut reasons);
    factors.sanitizer_absence = sanitizer_absence_score(
        &corpus,
        evidence_nodes,
        finding.static_proof_state,
        &mut reasons,
    );
    factors.framework_context = framework_context_score(&corpus, attack_surface, finding);
    if factors.framework_context > 0 {
        reasons.push("framework_context".to_string());
    }
    factors.codeql_flow_quality = codeql_flow_score(finding, evidence_nodes, &corpus, &mut reasons);
    factors.confidence = confidence_score(finding, &corpus, &mut reasons);
    factors.noise_adjustment = noise_adjustment(finding, evidence_nodes, &corpus, &mut reasons);

    let total = factors.severity
        + factors.static_proof
        + factors.attack_surface_reachability
        + factors.source_sink_class
        + factors.data_sensitivity
        + factors.privilege_boundary
        + factors.sanitizer_absence
        + factors.framework_context
        + factors.codeql_flow_quality
        + factors.confidence
        + factors.noise_adjustment;

    StaticImpactScore {
        total,
        factors,
        reasons,
    }
}

fn compare_ranked_findings(left: &StaticRankedFinding, right: &StaticRankedFinding) -> Ordering {
    right
        .impact
        .total
        .cmp(&left.impact.total)
        .then_with(|| severity_score_str(&right.severity).cmp(&severity_score_str(&left.severity)))
        .then_with(|| left.file_path.cmp(&right.file_path))
        .then_with(|| left.start_line.cmp(&right.start_line))
        .then_with(|| left.rule_id.cmp(&right.rule_id))
        .then_with(|| left.fingerprint.cmp(&right.fingerprint))
}

fn finding_corpus(finding: &Finding, evidence_nodes: &[StaticEvidenceNode]) -> String {
    let mut parts = vec![
        finding.rule_id.as_str(),
        finding.title.as_str(),
        finding.message.as_str(),
        finding.file_path.as_str(),
        finding.tool.as_str(),
    ];
    let mut owned = Vec::new();
    for node in evidence_nodes {
        parts.push(node.title.as_str());
        parts.push(node.body.as_str());
        if !node.metadata.is_null() {
            owned.push(node.metadata.to_string());
        }
    }
    for value in &owned {
        parts.push(value.as_str());
    }
    parts.join("\n").to_ascii_lowercase()
}

fn severity_score(severity: Severity) -> i32 {
    match severity {
        Severity::Critical => 30,
        Severity::High => 20,
        Severity::Medium => 10,
        Severity::Low => 4,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

fn severity_score_str(severity: &str) -> i32 {
    match severity {
        "critical" => 30,
        "high" => 20,
        "medium" => 10,
        "low" => 4,
        "info" => 1,
        _ => 0,
    }
}

fn static_proof_score(state: Option<StaticProofState>) -> i32 {
    match state {
        Some(StaticProofState::StaticallyConfirmed) => 32,
        Some(StaticProofState::SanitizerChecked) => 24,
        Some(StaticProofState::SourceSinkLinked) => 20,
        Some(StaticProofState::CodeCited) => 8,
        Some(StaticProofState::NeedsRuntimeEvidence) => 3,
        Some(StaticProofState::SignalOnly) | None => 0,
        Some(StaticProofState::StaticallyRejected) => -100,
    }
}

fn attack_surface_score(
    finding: &Finding,
    attack_surface: Option<&AttackSurfaceMap>,
    evidence_nodes: &[StaticEvidenceNode],
    reasons: &mut Vec<String>,
) -> i32 {
    let Some(surface_map) = attack_surface else {
        return 0;
    };
    let mut best = 0;
    for surface in &surface_map.surfaces {
        if surface_matches_finding(surface, finding, evidence_nodes) {
            let score = match surface.kind {
                AttackSurfaceKind::HttpRoute | AttackSurfaceKind::RpcHandler => 24,
                AttackSurfaceKind::CliEntrypoint => 18,
                AttackSurfaceKind::FileUploadParsePath => 20,
                AttackSurfaceKind::DeserializationPoint => 18,
                AttackSurfaceKind::DbQueryBoundary
                | AttackSurfaceKind::CommandExecutionBoundary => 16,
                AttackSurfaceKind::AuthBoundary => 14,
                AttackSurfaceKind::BackgroundJob => 10,
            };
            if score > best {
                best = score;
            }
        }
    }
    if best > 0 {
        reasons.push("attack_surface_reachable".to_string());
    }
    best
}

fn surface_matches_finding(
    surface: &AttackSurface,
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
) -> bool {
    if surface.path != finding.file_path
        && !evidence_nodes
            .iter()
            .any(|node| node.source_path.as_deref() == Some(surface.path.as_str()))
    {
        return false;
    }

    let Some(surface_line) = surface.line else {
        return true;
    };
    let finding_end = finding.end_line.unwrap_or(finding.start_line);
    if lines_overlap_or_near(surface_line, finding.start_line, finding_end, 12) {
        return true;
    }
    evidence_nodes.iter().any(|node| {
        node.source_path.as_deref() == Some(surface.path.as_str())
            && node.start_line.is_some_and(|line| {
                lines_overlap_or_near(surface_line, line, node.end_line.unwrap_or(line), 12)
            })
    })
}

fn lines_overlap_or_near(anchor: u32, start: u32, end: u32, window: u32) -> bool {
    let low = start.saturating_sub(window);
    let high = end.saturating_add(window);
    anchor >= low && anchor <= high
}

fn source_sink_score(corpus: &str, reasons: &mut Vec<String>) -> i32 {
    let classes: &[(&str, i32, &[&str])] = &[
        (
            "command_execution_sink",
            30,
            &[
                "child_process.exec",
                "os.system",
                "subprocess",
                "shell=true",
                "command execution",
            ],
        ),
        (
            "sql_sink",
            28,
            &[
                "sql injection",
                ".query(",
                "cursor.execute",
                "database query",
                "sequelize.query",
                "knex(",
            ],
        ),
        (
            "deserialization_sink",
            24,
            &[
                "deserialize",
                "pickle.loads",
                "yaml.load",
                "json.parse",
                "protobuf.decode",
            ],
        ),
        (
            "authz_boundary",
            22,
            &[
                "authorization",
                "authz",
                "access control",
                "permission",
                "tenant",
            ],
        ),
        (
            "file_write_or_path_sink",
            20,
            &[
                "path traversal",
                "file write",
                "writefile",
                "readfile",
                "open(",
            ],
        ),
        (
            "xss_sink",
            16,
            &[
                "cross-site scripting",
                "xss",
                "res.send",
                "innerhtml",
                "render(",
            ],
        ),
    ];

    for (label, score, needles) in classes {
        if contains_any(corpus, needles) {
            reasons.push((*label).to_string());
            return *score;
        }
    }
    0
}

fn data_sensitivity_score(corpus: &str, reasons: &mut Vec<String>) -> i32 {
    let sensitive = [
        "password",
        "secret",
        "token",
        "credential",
        "session",
        "cookie",
        "jwt",
        "ssn",
        "payment",
        "credit card",
        "admin",
        "tenant",
        "email",
        "pii",
    ];
    let hits = sensitive
        .iter()
        .filter(|needle| corpus.contains(**needle))
        .count() as i32;
    let score = (hits * 4).min(16);
    if score > 0 {
        reasons.push("sensitive_data_context".to_string());
    }
    score
}

fn privilege_boundary_score(
    corpus: &str,
    attack_surface: Option<&AttackSurfaceMap>,
    finding: &Finding,
    reasons: &mut Vec<String>,
) -> i32 {
    let mut score = if contains_any(
        corpus,
        &["auth", "admin", "role", "permission", "tenant", "privilege"],
    ) {
        12
    } else {
        0
    };

    if let Some(surface_map) = attack_surface {
        if surface_map.surfaces.iter().any(|surface| {
            surface.path == finding.file_path
                && matches!(surface.kind, AttackSurfaceKind::AuthBoundary)
        }) {
            score = score.max(16);
        }
        if surface_map.surfaces.iter().any(|surface| {
            surface.path == finding.file_path && surface.boundary.as_deref() == Some("public_http")
        }) {
            score = score.max(10);
        }
    }

    if score > 0 {
        reasons.push("privilege_or_trust_boundary".to_string());
    }
    score
}

fn sanitizer_absence_score(
    corpus: &str,
    evidence_nodes: &[StaticEvidenceNode],
    proof_state: Option<StaticProofState>,
    reasons: &mut Vec<String>,
) -> i32 {
    if proof_state == Some(StaticProofState::StaticallyRejected)
        || contains_any(
            corpus,
            &["sanitizer assessment: present", "sanitized_by", "sanitized"],
        )
        || evidence_nodes
            .iter()
            .any(|node| node.kind == StaticEvidenceNodeKind::Sanitizer)
    {
        reasons.push("sanitizer_or_guard_present".to_string());
        return -20;
    }
    if contains_any(
        corpus,
        &[
            "sanitizer assessment: absent",
            "sanitizer absent",
            "guard assessment: absent",
            "missing guard",
            "unsanitized",
        ],
    ) {
        reasons.push("sanitizer_or_guard_absent".to_string());
        return 14;
    }
    if matches!(
        proof_state,
        Some(StaticProofState::SourceSinkLinked | StaticProofState::SanitizerChecked)
    ) {
        return 6;
    }
    0
}

fn framework_context_score(
    corpus: &str,
    attack_surface: Option<&AttackSurfaceMap>,
    finding: &Finding,
) -> i32 {
    if let Some(surface_map) = attack_surface {
        if surface_map.surfaces.iter().any(|surface| {
            surface.path == finding.file_path
                && surface
                    .framework
                    .as_ref()
                    .is_some_and(|framework| !framework.trim().is_empty())
        }) {
            return 8;
        }
    }
    if contains_any(
        corpus,
        &[
            "express", "flask", "fastapi", "django", "gin", "actix", "rocket",
        ],
    ) {
        6
    } else {
        0
    }
}

fn codeql_flow_score(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
    corpus: &str,
    reasons: &mut Vec<String>,
) -> i32 {
    let dataflow_steps = evidence_nodes
        .iter()
        .filter(|node| node.kind == StaticEvidenceNodeKind::DataflowStep)
        .count() as i32;
    let metadata_steps = evidence_nodes
        .iter()
        .filter_map(|node| {
            node.metadata
                .pointer("/codeFlowStepCount")
                .and_then(serde_json::Value::as_i64)
        })
        .max()
        .unwrap_or(0)
        .max(0) as i32;
    let steps = dataflow_steps.max(metadata_steps);
    let mut score = if finding.tool == "codeql" { 8 } else { 0 };
    if steps > 0 {
        score += 6 + (steps * 4).min(18);
    } else if corpus.contains("code flow:") || corpus.contains("flows_to") {
        score += 10;
    }
    if score > 0 {
        reasons.push("codeql_flow_quality".to_string());
    }
    score
}

fn confidence_score(finding: &Finding, corpus: &str, reasons: &mut Vec<String>) -> i32 {
    if let Some(triage) = &finding.triage {
        let score = match triage.verdict {
            TriageVerdict::TruePositive => 10 + confidence_bucket_score(triage.confidence),
            TriageVerdict::FalsePositive | TriageVerdict::ByDesign => -40,
            TriageVerdict::NeedsReview => confidence_bucket_score(triage.confidence) / 2,
        };
        reasons.push(format!("triage_confidence={:.2}", triage.confidence));
        return score;
    }

    if contains_any(
        corpus,
        &[
            "confidence: high",
            "\"confidence\":\"high\"",
            "confidence high",
        ],
    ) {
        reasons.push("confidence=high".to_string());
        12
    } else if contains_any(
        corpus,
        &[
            "confidence: medium",
            "\"confidence\":\"medium\"",
            "confidence medium",
        ],
    ) {
        reasons.push("confidence=medium".to_string());
        7
    } else if contains_any(
        corpus,
        &[
            "confidence: low",
            "\"confidence\":\"low\"",
            "confidence low",
        ],
    ) {
        reasons.push("confidence=low".to_string());
        2
    } else {
        0
    }
}

fn confidence_bucket_score(confidence: f32) -> i32 {
    if confidence >= 0.85 {
        14
    } else if confidence >= 0.65 {
        9
    } else if confidence >= 0.45 {
        5
    } else {
        1
    }
}

fn noise_adjustment(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
    corpus: &str,
    reasons: &mut Vec<String>,
) -> i32 {
    let mut adjustment = 0;
    let has_dataflow = evidence_nodes
        .iter()
        .any(|node| node.kind == StaticEvidenceNodeKind::DataflowStep);
    let has_code_or_source_sink = evidence_nodes.iter().any(|node| {
        matches!(
            node.kind,
            StaticEvidenceNodeKind::CodeSpan
                | StaticEvidenceNodeKind::Source
                | StaticEvidenceNodeKind::Sink
        )
    });
    if finding.tool == "semgrep"
        && finding
            .static_proof_state
            .unwrap_or(StaticProofState::SignalOnly)
            == StaticProofState::SignalOnly
        && !has_dataflow
        && !has_code_or_source_sink
    {
        adjustment -= 14;
    }
    if contains_any(
        corpus,
        &[
            "generic",
            "style",
            "lint",
            "best practice",
            "dead code",
            "unused",
        ],
    ) {
        adjustment -= 8;
    }
    if adjustment < 0 {
        reasons.push("scanner_noise_penalty".to_string());
    }
    adjustment
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::attack_surface::{AttackSurfaceMap, AttackSurfaceSummary};
    use crate::findings::{TriageOutcome, TriageVerdict};
    use crate::static_evidence::{StaticEvidenceEdge, StaticEvidenceEdgeKind};

    #[test]
    fn static_ranking_high_impact_static_flow_outranks_generic_scanner_noise() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let mut static_flow = Finding::new_tool(
            "codeql",
            "js/sql-injection",
            "src/routes.ts",
            12,
            Some(30),
            Severity::Medium,
            "Source: req.query.userId\nSink: db.query(sql)\nSanitizer assessment: absent\nGuard assessment: absent\nConfidence: high\nCode flow: src/routes.ts:12 -> src/db.ts:30",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);
        static_flow.triage = Some(TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: 0.78,
            rationale: "static source-to-sink evidence".to_string(),
            ..Default::default()
        });
        let generic_noise = Finding::new_semgrep(
            "generic.best-practice.no-console",
            "src/util.ts",
            4,
            Some(4),
            Severity::Critical,
            "Generic lint noise: console statement.",
        )
        .with_static_proof_state(StaticProofState::SignalOnly);

        insert_flow_evidence(&store, &static_flow);
        let attack_surface = route_and_sink_surface();

        let ranked = rank_static_findings(
            &[generic_noise.clone(), static_flow.clone()],
            Some(&attack_surface),
            Some(&store),
        )
        .unwrap();

        assert_eq!(ranked[0].fingerprint, static_flow.fingerprint);
        assert_eq!(ranked[1].fingerprint, generic_noise.fingerprint);
        assert!(ranked[0].impact.total > ranked[1].impact.total);
        assert!(ranked[0].impact.factors.attack_surface_reachability > 0);
        assert!(ranked[0].impact.factors.source_sink_class > 0);
        assert!(ranked[0].impact.factors.data_sensitivity > 0);
        assert!(ranked[0].impact.factors.privilege_boundary > 0);
        assert!(ranked[0].impact.factors.sanitizer_absence > 0);
        assert!(ranked[0].impact.factors.framework_context > 0);
        assert!(ranked[0].impact.factors.codeql_flow_quality > 0);
        assert!(ranked[0].impact.factors.confidence > 0);
        assert!(ranked[1].impact.factors.noise_adjustment < 0);
    }

    #[test]
    fn static_ranking_is_deterministic_for_equal_scores() {
        let first = Finding::new_tool(
            "semgrep",
            "generic.rule",
            "src/a.ts",
            3,
            Some(3),
            Severity::Low,
            "generic signal",
        );
        let second = Finding::new_tool(
            "semgrep",
            "generic.rule",
            "src/b.ts",
            3,
            Some(3),
            Severity::Low,
            "generic signal",
        );

        let one = rank_static_findings(&[second.clone(), first.clone()], None, None).unwrap();
        let two = rank_static_findings(&[first.clone(), second.clone()], None, None).unwrap();

        let one_order = one
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect::<Vec<_>>();
        let two_order = two
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect::<Vec<_>>();
        assert_eq!(one_order, two_order);
        assert_eq!(one_order[0], first.fingerprint);
    }

    #[test]
    fn static_ranking_downranks_sanitized_or_rejected_findings() {
        let sanitized = Finding::new_tool(
            "agentic",
            "validated-input",
            "src/routes.ts",
            10,
            Some(10),
            Severity::High,
            "Sanitizer assessment: present\nInput is sanitized before the sink.",
        )
        .with_static_proof_state(StaticProofState::StaticallyRejected);
        let unsanitized = Finding::new_tool(
            "agentic",
            "missing-validation",
            "src/routes.ts",
            11,
            Some(11),
            Severity::Medium,
            "Sanitizer assessment: absent\nreq.body.password reaches db.query.",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);

        let ranked = rank_static_findings(&[sanitized, unsanitized.clone()], None, None).unwrap();

        assert_eq!(ranked[0].fingerprint, unsanitized.fingerprint);
        assert!(ranked[1].impact.total < 0);
    }

    fn insert_flow_evidence(store: &StaticEvidenceStore, finding: &Finding) {
        let source = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::Source,
            "Express request source",
            "const userId = req.query.userId;",
        )
        .with_finding_fingerprint(&finding.fingerprint)
        .with_source_span("src/routes.ts", 12, Some(12))
        .with_metadata(json!({"framework": "Express", "data": "user token"}));
        let sink = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::Sink,
            "Database query sink",
            "return db.query(sql);",
        )
        .with_finding_fingerprint(&finding.fingerprint)
        .with_source_span("src/db.ts", 30, Some(30))
        .with_metadata(json!({"sinkClass": "sql_query", "data": "tenant data"}));
        let step = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::DataflowStep,
            "CodeQL dataflow step",
            "CodeQL links req.query.userId to db.query(sql)",
        )
        .with_finding_fingerprint(&finding.fingerprint)
        .with_source_span("src/routes.ts", 18, Some(18))
        .with_metadata(json!({"normalizer": "codeql", "sequence": 1, "codeFlowStepCount": 3}));

        store.upsert_node(&source).unwrap();
        store.upsert_node(&sink).unwrap();
        store.upsert_node(&step).unwrap();
        store
            .upsert_edge(
                &StaticEvidenceEdge::new(StaticEvidenceEdgeKind::FlowsTo, source.id, step.id)
                    .with_finding_fingerprint(&finding.fingerprint),
            )
            .unwrap();
    }

    fn route_and_sink_surface() -> AttackSurfaceMap {
        let surfaces = vec![
            AttackSurface {
                id: "route".to_string(),
                kind: AttackSurfaceKind::HttpRoute,
                path: "src/routes.ts".to_string(),
                line: Some(10),
                language: "TypeScript".to_string(),
                framework: Some("Express".to_string()),
                title: "GET /users/:id".to_string(),
                evidence: "app.get('/users/:id', handler)".to_string(),
                method: Some("GET".to_string()),
                route: Some("/users/:id".to_string()),
                boundary: Some("public_http".to_string()),
                metadata: json!({}),
            },
            AttackSurface {
                id: "db".to_string(),
                kind: AttackSurfaceKind::DbQueryBoundary,
                path: "src/db.ts".to_string(),
                line: Some(30),
                language: "TypeScript".to_string(),
                framework: None,
                title: "database query".to_string(),
                evidence: "db.query(sql)".to_string(),
                method: None,
                route: None,
                boundary: Some("data_store".to_string()),
                metadata: json!({}),
            },
        ];
        AttackSurfaceMap {
            root_name: "fixture".to_string(),
            summary: AttackSurfaceSummary {
                total: surfaces.len(),
                by_kind: Default::default(),
                by_file: Default::default(),
            },
            surfaces,
        }
    }
}
