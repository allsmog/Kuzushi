use super::*;

const MAX_OMISSION_RULE_SAMPLES: usize = 5;
const MAX_OMISSION_RULE_CHARS: usize = 80;

#[derive(Debug, Default)]
pub(in crate::scan) struct CodeqlNormalizationOutcome {
    pub(in crate::scan) findings: Vec<Finding>,
    pub(in crate::scan) scan_errors: Vec<String>,
}

#[derive(Debug, Default)]
struct CodeqlNormalizationOmissions {
    count: usize,
    rule_samples: Vec<String>,
}

impl CodeqlNormalizationOmissions {
    fn record(&mut self, result: &CodeqlSarifResult) {
        self.count += 1;
        if self.rule_samples.len() < MAX_OMISSION_RULE_SAMPLES {
            self.rule_samples
                .push(bounded_codeql_rule_id(result.rule_id.as_deref()));
        }
    }

    fn into_scan_errors(self) -> Vec<String> {
        if self.count == 0 {
            return Vec::new();
        }
        let suffix = if self.rule_samples.is_empty() {
            String::new()
        } else {
            format!("; sample rules: {}", self.rule_samples.join(", "))
        };
        vec![format!(
            "CodeQL SARIF omitted {} result{} without a usable physical location{}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            suffix
        )]
    }
}

pub fn normalize_codeql_sarif(raw: &str, repo_name: &str) -> Result<Vec<Finding>> {
    let outcome = normalize_codeql_sarif_with_diagnostics(raw, repo_name)?;
    if let Some(error) = outcome.scan_errors.first() {
        anyhow::bail!("{error}");
    }
    Ok(outcome.findings)
}

pub(in crate::scan) fn normalize_codeql_sarif_with_diagnostics(
    raw: &str,
    repo_name: &str,
) -> Result<CodeqlNormalizationOutcome> {
    let report = parse_codeql_sarif(raw)?;
    let mut outcome = normalize_codeql_report(&report);
    sort_codeql_findings(&mut outcome.findings);
    let _ = repo_name;
    Ok(outcome)
}

fn normalize_codeql_report(report: &CodeqlSarifOutput) -> CodeqlNormalizationOutcome {
    let mut findings = Vec::new();
    let mut omissions = CodeqlNormalizationOmissions::default();

    for run in &report.runs {
        let rules_by_id = codeql_rules_by_id(run);
        for result in &run.results {
            match normalize_codeql_result_to_finding(result, &rules_by_id) {
                Some(finding) => findings.push(finding),
                None => omissions.record(result),
            }
        }
    }

    CodeqlNormalizationOutcome {
        findings,
        scan_errors: omissions.into_scan_errors(),
    }
}

fn codeql_rules_by_id(run: &CodeqlSarifRun) -> HashMap<String, CodeqlSarifRule> {
    run.tool
        .as_ref()
        .and_then(|tool| tool.driver.as_ref())
        .map(|driver| {
            driver
                .rules
                .iter()
                .filter_map(|rule| rule.id.clone().map(|id| (id, rule.clone())))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default()
}

fn sort_codeql_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        severity_rank(right.severity)
            .cmp(&severity_rank(left.severity))
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.start_line.cmp(&right.start_line))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
}

fn bounded_codeql_rule_id(rule_id: Option<&str>) -> String {
    let value = rule_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("codeql.unknown");
    let mut chars = value.chars();
    let mut bounded = String::new();
    for ch in chars.by_ref().take(MAX_OMISSION_RULE_CHARS) {
        bounded.push(if ch.is_control() { ' ' } else { ch });
    }
    if chars.next().is_some() {
        bounded.push('…');
    }
    bounded
}

/// Indexes a scan's SARIF documents as one unit: every document is
/// preflighted before the first write, so a later ungroundable document
/// cannot leave evidence from earlier documents behind a failed scan.
pub fn index_codeql_sarif_documents_as_static_evidence(
    store: &StaticEvidenceStore,
    repo_root: impl AsRef<Path>,
    documents: &[String],
) -> Result<Vec<StaticEvidenceIndexReport>> {
    for raw in documents {
        preflight_codeql_static_evidence(&parse_codeql_sarif(raw)?)?;
    }
    documents
        .iter()
        .map(|raw| index_codeql_sarif_as_static_evidence(store, repo_root.as_ref(), raw))
        .collect()
}

fn parse_codeql_sarif(raw: &str) -> Result<CodeqlSarifOutput> {
    serde_json::from_str(raw).context("Could not parse CodeQL SARIF output")
}

fn preflight_codeql_static_evidence(report: &CodeqlSarifOutput) -> Result<()> {
    let preflight = normalize_codeql_report(report);
    if let Some(error) = preflight.scan_errors.first() {
        anyhow::bail!("Could not index CodeQL static evidence: {error}");
    }
    Ok(())
}

/// Index a CodeQL SARIF document, refusing it outright when any result cannot
/// be grounded. Public callers get no silently partial static-evidence copy.
pub fn index_codeql_sarif_as_static_evidence(
    store: &StaticEvidenceStore,
    repo_root: impl AsRef<Path>,
    raw: &str,
) -> Result<StaticEvidenceIndexReport> {
    let report = parse_codeql_sarif(raw)?;
    preflight_codeql_static_evidence(&report)?;
    index_codeql_report(store, repo_root.as_ref(), &report)
}

/// Index a scan's SARIF documents after the scan engine has already disclosed
/// their omissions through `scan_errors`. Every document parses before the
/// first write; each report then carries its grounded results and the count
/// of location-less ones (`resultsOmitted`), so one ungroundable result does
/// not discard the evidence for its grounded siblings.
pub(crate) fn index_grounded_codeql_sarif_documents_as_static_evidence(
    store: &StaticEvidenceStore,
    repo_root: impl AsRef<Path>,
    documents: &[String],
) -> Result<Vec<StaticEvidenceIndexReport>> {
    let reports = documents
        .iter()
        .map(|raw| parse_codeql_sarif(raw))
        .collect::<Result<Vec<_>>>()?;
    reports
        .iter()
        .map(|report| index_codeql_report(store, repo_root.as_ref(), report))
        .collect()
}

fn index_codeql_report(
    store: &StaticEvidenceStore,
    repo_root: &Path,
    report: &CodeqlSarifOutput,
) -> Result<StaticEvidenceIndexReport> {
    let mut index_report = StaticEvidenceIndexReport::new(store.db_path());
    for run in &report.runs {
        let rules_by_id = codeql_rules_by_id(run);
        for result in &run.results {
            match normalize_codeql_result_to_finding(result, &rules_by_id) {
                Some(finding) => {
                    index_codeql_finding(store, repo_root, finding, result, &mut index_report)?
                }
                None => index_report.results_omitted += 1,
            }
        }
    }
    Ok(index_report)
}

fn index_codeql_finding(
    store: &StaticEvidenceStore,
    repo_root: &Path,
    mut finding: Finding,
    result: &CodeqlSarifResult,
    index_report: &mut StaticEvidenceIndexReport,
) -> Result<()> {
    finding.set_static_proof_state(StaticProofState::SignalOnly);
    let indexed = index_codeql_result_as_static_evidence(store, repo_root, &finding, result)
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIXED_SARIF: &str = r#"{
      "runs": [{
        "tool": {"driver": {"rules": [{"id": "good.rule"}, {"id": "lost.rule"}]}},
        "results": [
          {
            "ruleId": "good.rule",
            "message": {"text": "grounded result"},
            "locations": [{
              "physicalLocation": {
                "artifactLocation": {"uri": "src/lib.rs"},
                "region": {"startLine": 7}
              }
            }]
          },
          {
            "ruleId": "lost.rule",
            "message": {"text": "result without a location"},
            "locations": []
          }
        ]
      }]
    }"#;

    #[test]
    fn detailed_normalization_keeps_findings_and_accounts_for_omissions() {
        let outcome = normalize_codeql_sarif_with_diagnostics(MIXED_SARIF, "repo").unwrap();

        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].rule_id, "good.rule");
        assert_eq!(outcome.scan_errors.len(), 1);
        assert!(outcome.scan_errors[0].contains("1 result"));
        assert!(outcome.scan_errors[0].contains("lost.rule"));
        assert!(outcome.scan_errors[0].contains("usable physical location"));
    }

    #[test]
    fn compatibility_normalizer_refuses_to_silently_drop_a_sarif_result() {
        let error = normalize_codeql_sarif(MIXED_SARIF, "repo").unwrap_err();

        assert!(error.to_string().contains("lost.rule"));
        assert!(error.to_string().contains("usable physical location"));
    }

    #[test]
    fn static_evidence_indexing_refuses_normalization_loss_before_writing() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let error = index_codeql_sarif_as_static_evidence(&store, ".", MIXED_SARIF).unwrap_err();

        assert!(error
            .to_string()
            .contains("Could not index CodeQL static evidence"));
        assert!(error.to_string().contains("lost.rule"));
    }

    const GROUNDED_SARIF: &str = r#"{
      "runs": [{
        "tool": {"driver": {"rules": [{"id": "good.rule"}]}},
        "results": [{
          "ruleId": "good.rule",
          "message": {"text": "grounded result"},
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {"uri": "src/lib.rs"},
              "region": {"startLine": 7}
            }
          }]
        }]
      }]
    }"#;

    #[test]
    fn document_collection_with_one_ungroundable_document_writes_no_evidence() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let documents = vec![GROUNDED_SARIF.to_string(), MIXED_SARIF.to_string()];

        let error =
            index_codeql_sarif_documents_as_static_evidence(&store, ".", &documents).unwrap_err();

        assert!(error.to_string().contains("lost.rule"), "{error}");
        let grounded = normalize_codeql_sarif(GROUNDED_SARIF, "repo").unwrap();
        let nodes = store
            .list_nodes_for_finding(&grounded[0].fingerprint)
            .unwrap();
        assert!(nodes.is_empty(), "earlier document leaked evidence: {nodes:?}");
    }

    #[test]
    fn document_collection_indexes_every_groundable_document() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let documents = vec![GROUNDED_SARIF.to_string()];

        let reports =
            index_codeql_sarif_documents_as_static_evidence(&store, ".", &documents).unwrap();

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].findings_indexed, 1);
    }

    #[test]
    fn scan_indexing_keeps_grounded_results_and_counts_the_omission() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let documents = vec![GROUNDED_SARIF.to_string(), MIXED_SARIF.to_string()];

        let reports =
            index_grounded_codeql_sarif_documents_as_static_evidence(&store, ".", &documents)
                .unwrap();

        assert_eq!(reports[0].findings_indexed, 1);
        assert_eq!(reports[1].findings_indexed, 1);
        assert_eq!(reports[1].results_omitted, 1);
    }

    #[test]
    fn scan_indexing_parses_every_document_before_writing() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let documents = vec![GROUNDED_SARIF.to_string(), "not json".to_string()];

        assert!(
            index_grounded_codeql_sarif_documents_as_static_evidence(&store, ".", &documents)
                .is_err()
        );
        let grounded = normalize_codeql_sarif(GROUNDED_SARIF, "repo").unwrap();
        assert!(store
            .list_nodes_for_finding(&grounded[0].fingerprint)
            .unwrap()
            .is_empty());
    }
}
