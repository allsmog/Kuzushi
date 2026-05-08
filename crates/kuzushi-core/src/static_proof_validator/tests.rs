#[cfg(test)]
mod tests {
    use std::fs;

    use crate::static_evidence::static_content_hash;
    use serde_json::json;

    use super::super::*;

    #[test]
    fn static_proof_validator_accepts_fully_cited_confirmed_claim() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "app.get('/search', requireAuth, (req, res) => {\n  const q = req.query.q;\n  return db.query(`select * from users where name = ${q}`);\n});\n",
        )
        .unwrap();

        let citation = StaticProofCitation::new("src/routes.ts", 1, 3);
        let claim = StaticProofClaim {
            requested_state: StaticProofState::StaticallyConfirmed,
            source_or_entrypoint_evidence: vec![StaticProofEvidence::new(
                "HTTP route",
                "GET /search reads req.query.q",
            )
            .with_citation(citation.clone())],
            sink_evidence: vec![StaticProofEvidence::new(
                "SQL query",
                "db.query receives the route value",
            )
            .with_citation(StaticProofCitation::new("src/routes.ts", 3, 3))],
            path_explanation: Some(
                "The route reads req.query.q and directly interpolates it into db.query."
                    .to_string(),
            ),
            local_direct_reason: None,
            sanitizer_assessment: StaticProofAssessment::new(
                StaticProofAssessmentStatus::Absent,
                "No validation or escaping is present between source and sink.",
            ),
            guard_assessment: StaticProofAssessment::new(
                StaticProofAssessmentStatus::Present,
                "requireAuth gates the route, so the static claim is authenticated-user scoped.",
            ),
            citations: vec![citation],
            assumptions: vec![
                "Static analysis assumes Express route wiring is reachable.".to_string()
            ],
            missing_evidence: vec![
                "Runtime reachability and exploitability are not assessed in whitebox-static mode."
                    .to_string(),
            ],
        };

        let validation = validate_static_proof_claim(temp.path(), &claim);

        assert!(validation.accepted, "{:?}", validation.issues);
        assert_eq!(
            validation.final_state,
            StaticProofState::StaticallyConfirmed
        );
        assert_eq!(validation.final_verdict, TriageVerdict::TruePositive);
        assert_eq!(validation.verified_citations.len(), 2);
    }

    #[test]
    fn static_proof_validator_downgrades_confirmed_claim_without_required_proof() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("app.ts"), "const x = 1;\n").unwrap();

        let claim = StaticProofClaim {
            requested_state: StaticProofState::StaticallyConfirmed,
            source_or_entrypoint_evidence: Vec::new(),
            sink_evidence: Vec::new(),
            path_explanation: None,
            local_direct_reason: None,
            sanitizer_assessment: StaticProofAssessment::new(
                StaticProofAssessmentStatus::Unknown,
                "",
            ),
            guard_assessment: StaticProofAssessment::new(StaticProofAssessmentStatus::Unknown, ""),
            citations: Vec::new(),
            assumptions: Vec::new(),
            missing_evidence: Vec::new(),
        };

        let validation = validate_static_proof_claim(temp.path(), &claim);

        assert!(!validation.accepted);
        assert_eq!(
            validation.final_state,
            StaticProofState::NeedsRuntimeEvidence
        );
        assert_eq!(validation.final_verdict, TriageVerdict::NeedsReview);
        assert!(validation
            .issues
            .iter()
            .any(|issue| issue.contains("source or entrypoint")));
        assert!(validation
            .issues
            .iter()
            .any(|issue| issue.contains("sink or security-sensitive")));
        assert!(validation
            .issues
            .iter()
            .any(|issue| issue.contains("verified code citation")));
    }

    #[test]
    fn static_proof_validator_rejects_stale_or_fabricated_citations() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("route.ts"), "const q = req.query.q;\n").unwrap();
        let stale_hash = static_content_hash("old source");
        let citation = StaticProofCitation::new("route.ts", 1, 1)
            .with_snippet("const q = req.query.q;")
            .with_snippet_hash(stale_hash);
        let claim = minimally_confirmed_claim(citation);

        let validation = validate_static_proof_claim(temp.path(), &claim);

        assert!(!validation.accepted);
        assert_eq!(
            validation.final_state,
            StaticProofState::NeedsRuntimeEvidence
        );
        assert!(validation
            .issues
            .iter()
            .any(|issue| issue.contains("snippet hash mismatch")));
    }

    #[test]
    fn whitebox_citations_verify_file_lines_snippet_and_hash() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "const q = req.query.q;\ndb.query(q);\n",
        )
        .unwrap();
        let snippet = "const q = req.query.q;\ndb.query(q);";
        let citation = StaticProofCitation::new("src/routes.ts", 1, 2)
            .with_snippet(snippet)
            .with_snippet_hash(static_content_hash(snippet));

        let verified = verify_static_proof_citation(temp.path(), &citation).unwrap();

        assert_eq!(verified.file_path, "src/routes.ts");
        assert_eq!(verified.start_line, 1);
        assert_eq!(verified.end_line, 2);
        assert_eq!(verified.snippet_hash, static_content_hash(snippet));
    }

    #[test]
    fn whitebox_citations_reject_out_of_repo_missing_lines_and_stale_snippets() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("route.ts"), "const q = req.query.q;\n").unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "const secret = true;\n").unwrap();

        let out_of_repo = verify_static_proof_citation(
            temp.path(),
            &StaticProofCitation::new(outside.path().display().to_string(), 1, 1),
        )
        .unwrap_err()
        .to_string();
        let missing_line =
            verify_static_proof_citation(temp.path(), &StaticProofCitation::new("route.ts", 1, 3))
                .unwrap_err()
                .to_string();
        let stale_snippet = verify_static_proof_citation(
            temp.path(),
            &StaticProofCitation::new("route.ts", 1, 1).with_snippet("const q = req.body.q;"),
        )
        .unwrap_err()
        .to_string();

        assert!(
            out_of_repo.contains("outside repository root"),
            "{out_of_repo}"
        );
        assert!(
            missing_line.contains("exceeds file line count"),
            "{missing_line}"
        );
        assert!(
            stale_snippet.contains("snippet text does not match"),
            "{stale_snippet}"
        );
    }

    #[test]
    fn whitebox_citations_parse_llm_schema_into_static_proof_claim() {
        let raw = json!({
            "staticProofState": "statically_confirmed",
            "source": {
                "kind": "attacker_input",
                "filePath": "src/routes.ts",
                "startLine": 1,
                "endLine": 1,
                "description": "req.query.q is read"
            },
            "sink": {
                "kind": "sql_query",
                "filePath": "src/routes.ts",
                "startLine": 2,
                "endLine": 2,
                "description": "db.query receives q"
            },
            "path": {"kind": "direct", "explanation": "q is passed directly"},
            "sanitizerAssessment": {"status": "absent", "explanation": "none"},
            "guardAssessment": {"status": "present", "explanation": "requireAuth"},
            "citations": [{
                "filePath": "src/routes.ts",
                "startLine": 1,
                "endLine": 2,
                "snippet": "const q = req.query.q;\ndb.query(q);",
                "snippetHash": "hash"
            }],
            "assumptions": ["static route wiring"],
            "missingEvidence": ["runtime evidence"]
        });

        let claim = static_proof_claim_from_whitebox_schema(&raw).unwrap();

        assert_eq!(claim.requested_state, StaticProofState::StaticallyConfirmed);
        assert_eq!(claim.source_or_entrypoint_evidence.len(), 1);
        assert_eq!(claim.sink_evidence.len(), 1);
        assert_eq!(
            claim.sanitizer_assessment.status,
            StaticProofAssessmentStatus::Absent
        );
        assert_eq!(
            claim.guard_assessment.status,
            StaticProofAssessmentStatus::Present
        );
        assert_eq!(claim.citations.len(), 1);
        assert_eq!(claim.assumptions, vec!["static route wiring"]);
        assert_eq!(claim.missing_evidence, vec!["runtime evidence"]);
    }

    #[test]
    fn static_proof_validator_blocks_runtime_exploitability_language() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("route.ts"), "exec(req.query.cmd);\n").unwrap();
        let citation = StaticProofCitation::new("route.ts", 1, 1);
        let mut claim = minimally_confirmed_claim(citation);
        claim.path_explanation = Some("This is runtime exploitable from the route.".to_string());

        let validation = validate_static_proof_claim(temp.path(), &claim);

        assert!(!validation.accepted);
        assert_eq!(
            validation.final_state,
            StaticProofState::NeedsRuntimeEvidence
        );
        assert!(validation
            .issues
            .iter()
            .any(|issue| issue.contains("runtime exploitability")));
    }

    fn minimally_confirmed_claim(citation: StaticProofCitation) -> StaticProofClaim {
        StaticProofClaim {
            requested_state: StaticProofState::StaticallyConfirmed,
            source_or_entrypoint_evidence: vec![
                StaticProofEvidence::new("route", "route source").with_citation(citation.clone())
            ],
            sink_evidence: vec![
                StaticProofEvidence::new("sink", "security-sensitive operation")
                    .with_citation(citation.clone()),
            ],
            path_explanation: Some("Source reaches sink in the cited local handler.".to_string()),
            local_direct_reason: None,
            sanitizer_assessment: StaticProofAssessment::new(
                StaticProofAssessmentStatus::Absent,
                "No sanitizer is present in the cited local span.",
            ),
            guard_assessment: StaticProofAssessment::new(
                StaticProofAssessmentStatus::NotApplicable,
                "No authz claim is required for this local static proof.",
            ),
            citations: vec![citation],
            assumptions: vec!["Static call wiring is interpreted from source only.".to_string()],
            missing_evidence: vec!["Runtime execution is intentionally not performed.".to_string()],
        }
    }
}
