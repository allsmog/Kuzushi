#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::findings::{Finding, Severity, StaticProofState};
    use crate::static_ranking::{StaticImpactFactors, StaticImpactScore, StaticRankedFinding};

    #[test]
    fn static_narrative_report_includes_trigger_impact_and_limits() {
        let finding = Finding::new_tool(
            "codeql",
            "js/sql-injection",
            "src/routes.ts",
            10,
            Some(12),
            Severity::High,
            "SQL query uses request input",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);
        let ranked = ranked_for(&finding, 1, 94);

        let report = build_static_narrative_report(&[finding], &[ranked]).unwrap();

        assert_eq!(report.count, 1);
        let narrative = &report.narratives[0];
        assert!(narrative
            .static_trigger_path
            .contains("Static trigger path"));
        assert!(narrative
            .static_trigger_path
            .contains("src/routes.ts:10-12"));
        assert!(narrative.potential_impact.contains("Potential impact"));
        assert!(narrative.evidence_limits.contains("Evidence limits"));
        assert!(narrative.evidence_limits.contains("Runtime reachability"));
        assert_eq!(narrative.rank, Some(1));
        assert_eq!(narrative.static_impact_score, Some(94));
        assert_no_forbidden_language(narrative);
    }

    #[test]
    fn static_narrative_validation_rejects_exploit_and_poc_language() {
        for bad in [
            "The issue was exploited through the route.",
            "This is a confirmed exploit.",
            "PoC payload: curl http://127.0.0.1",
        ] {
            let error = validate_static_narrative_text(
                "Static trigger path: source reaches sink.",
                bad,
                "Evidence limits: runtime behavior is not assessed.",
            )
            .unwrap_err()
            .to_string();

            assert!(
                error.contains("forbidden term"),
                "unexpected error for {bad:?}: {error}"
            );
        }
    }

    #[test]
    fn static_narratives_are_ordered_by_static_rank_then_location() {
        let high = Finding::new_tool(
            "codeql",
            "js/sql-injection",
            "src/b.ts",
            20,
            Some(20),
            Severity::High,
            "source reaches sink",
        );
        let low = Finding::new_tool(
            "semgrep",
            "generic.warning",
            "src/a.ts",
            2,
            Some(2),
            Severity::Medium,
            "generic warning",
        );
        let high_ranked = ranked_for(&high, 1, 80);
        let low_ranked = ranked_for(&low, 2, 10);

        let report =
            build_static_narrative_report(&[low.clone(), high.clone()], &[low_ranked, high_ranked])
                .unwrap();

        assert_eq!(report.narratives[0].fingerprint, high.fingerprint);
        assert_eq!(report.narratives[1].fingerprint, low.fingerprint);
    }

    fn ranked_for(finding: &Finding, rank: usize, total: i32) -> StaticRankedFinding {
        StaticRankedFinding {
            rank,
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
            impact: StaticImpactScore {
                total,
                factors: StaticImpactFactors::default(),
                reasons: vec!["attack_surface_reachable".to_string()],
            },
        }
    }

    fn assert_no_forbidden_language(narrative: &StaticFindingNarrative) {
        validate_static_narrative_text(
            &narrative.static_trigger_path,
            &narrative.potential_impact,
            &narrative.evidence_limits,
        )
        .unwrap();
    }
}
