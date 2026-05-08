use super::*;

pub fn normalize_codeql_sarif(raw: &str, repo_name: &str) -> Result<Vec<Finding>> {
    let report: CodeqlSarifOutput =
        serde_json::from_str(raw).context("Could not parse CodeQL SARIF output")?;
    let mut findings = Vec::new();

    for run in report.runs {
        let rules_by_id = run
            .tool
            .and_then(|tool| tool.driver)
            .map(|driver| {
                driver
                    .rules
                    .into_iter()
                    .filter_map(|rule| rule.id.clone().map(|id| (id, rule)))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();

        for result in run.results {
            let Some(finding) = normalize_codeql_result_to_finding(&result, &rules_by_id) else {
                continue;
            };
            findings.push(finding);
        }
    }

    findings.sort_by(|left, right| {
        severity_rank(right.severity)
            .cmp(&severity_rank(left.severity))
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.start_line.cmp(&right.start_line))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    let _ = repo_name;
    Ok(findings)
}

pub fn index_codeql_sarif_as_static_evidence(
    store: &StaticEvidenceStore,
    repo_root: impl AsRef<Path>,
    raw: &str,
) -> Result<StaticEvidenceIndexReport> {
    let report: CodeqlSarifOutput =
        serde_json::from_str(raw).context("Could not parse CodeQL SARIF output")?;
    let mut index_report = StaticEvidenceIndexReport {
        db_path: store.db_path().to_string(),
        findings_indexed: 0,
        nodes_indexed: 0,
        edges_indexed: 0,
        node_ids: Vec::new(),
        edge_ids: Vec::new(),
    };
    let repo_root = repo_root.as_ref();

    for run in report.runs {
        let rules_by_id = run
            .tool
            .and_then(|tool| tool.driver)
            .map(|driver| {
                driver
                    .rules
                    .into_iter()
                    .filter_map(|rule| rule.id.clone().map(|id| (id, rule)))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();

        for result in run.results {
            let Some(mut finding) = normalize_codeql_result_to_finding(&result, &rules_by_id)
            else {
                continue;
            };
            finding.set_static_proof_state(StaticProofState::SignalOnly);
            let indexed =
                index_codeql_result_as_static_evidence(store, repo_root, &finding, &result)
                    .with_context(|| {
                        format!(
                            "Could not index CodeQL static evidence for {} at {}:{}",
                            finding.rule_id, finding.file_path, finding.start_line
                        )
                    })?;

            index_report.findings_indexed += 1;
            index_report.nodes_indexed += indexed.nodes_indexed;
            index_report.edges_indexed += indexed.edges_indexed;
            index_report.node_ids.extend(indexed.node_ids);
            index_report.edge_ids.extend(indexed.edge_ids);
        }
    }

    Ok(index_report)
}
