#[cfg(test)]
mod tests {
    use super::super::*;
    use regex::Regex;
    use std::path::{Path, PathBuf};

    fn finding_row(file: &str, line: u32, message: &str) -> FindingRow {
        FindingRow {
            fingerprint: format!("fp-{file}-{line}"),
            rule_id: "test.rule".to_string(),
            title: String::new(),
            severity: "high".to_string(),
            file_path: file.to_string(),
            start_line: line,
            end_line: Some(line),
            message: message.to_string(),
            tool: "semgrep".to_string(),
            vuln_source: None,
            static_proof_state: None,
            verdict: None,
            triage: None,
        }
    }

    fn cli() -> Cli {
        Cli {
            oracle: PathBuf::from("/tmp/o.json"),
            findings: PathBuf::from("/tmp/f.json"),
            slice: "test".to_string(),
            target: PathBuf::from("/tmp"),
            wall_seconds: 0,
            pretty: true,
        }
    }

    #[test]
    fn tolerance_priority_and_labels_are_ordered_by_match_strength() {
        assert_eq!(Tolerance::ExactLine.priority(), 4);
        assert_eq!(Tolerance::PmLines.priority(), 3);
        assert_eq!(Tolerance::Function.priority(), 2);
        assert_eq!(Tolerance::FileOnly.priority(), 1);
        assert_eq!(Tolerance::ExactLine.as_str(), "exact_line");
        assert_eq!(Tolerance::FileOnly.as_str(), "file_only");
    }

    #[test]
    fn path_matches_directory_oracle() {
        assert!(path_matches("crypto/skcipher.c", "crypto/"));
        assert!(path_matches("crypto/sub/foo.c", "crypto/"));
        assert!(!path_matches("lib/foo.c", "crypto/"));
    }

    #[test]
    fn cwe_extraction_pulls_from_message_rule_and_title() {
        let re = Regex::new(r"CWE-(\d+)").unwrap();
        let mut f = finding_row("foo.c", 1, "OOB write CWE-787 in handler");
        f.rule_id = "checks.cwe-78.shell-injection".to_string();
        f.title = "command injection (CWE-78)".to_string();
        let cwes = extract_cwes(&re, &f);
        assert!(cwes.contains(&"CWE-78".to_string()));
        assert!(cwes.contains(&"CWE-787".to_string()));
    }

    #[test]
    fn score_emits_pm10_hit_when_finding_within_window_with_cwe() {
        let oracle = Oracle {
            cve: "CVE-TEST".to_string(),
            slice: Some("test".to_string()),
            name: None,
            commit: None,
            ground_truth: vec![OracleEntry {
                file: "src/foo.c".to_string(),
                function: String::new(),
                line_start: 100,
                line_end: 100,
                cwe: vec!["CWE-78".to_string()],
                kind: String::new(),
                notes: String::new(),
                expected_verdict: None,
                expected_severity: None,
            }],
            expected_min_recall: None,
            notes: None,
        };
        let dump = FindingsDump {
            count: 1,
            findings: vec![finding_row(
                "src/foo.c",
                105,
                "command injection CWE-78 via exec()",
            )],
        };
        let report = score(&cli(), &oracle, &dump, Path::new("/tmp"));
        assert_eq!(report.hits, 1);
        assert_eq!(report.recall.pm_lines, 1.0);
        assert_eq!(report.recall.exact_line, 0.0);
    }

    #[test]
    fn load_match_report_reads_json_files_and_renderer_respects_pretty_flag() {
        let temp = std::env::temp_dir().join(format!(
            "kuzushi-eval-load-report-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let oracle = temp.join("oracle.json");
        let findings = temp.join("findings.json");
        std::fs::write(
            &oracle,
            r#"{
                "cve":"CVE-TEST",
                "ground_truth":[{
                    "file":"src/foo.c",
                    "line_start":10,
                    "line_end":10,
                    "cwe":["CWE-787"]
                }]
            }"#,
        )
        .unwrap();
        std::fs::write(
            &findings,
            r#"{
                "count":1,
                "findings":[{
                    "fingerprint":"fp",
                    "rule_id":"test.cwe-787",
                    "severity":"high",
                    "file_path":"src/foo.c",
                    "start_line":10,
                    "message":"CWE-787",
                    "tool":"semgrep"
                }]
            }"#,
        )
        .unwrap();
        let cli = Cli {
            oracle,
            findings,
            slice: "test".to_string(),
            target: temp,
            wall_seconds: 0,
            pretty: false,
        };

        let report = load_match_report(&cli).unwrap();
        assert_eq!(report.hits, 1);
        assert!(!render_match_report(&report, false).unwrap().contains('\n'));
        assert!(render_match_report(&report, true).unwrap().contains('\n'));
    }

    #[test]
    fn score_demotes_to_file_only_when_cwe_mismatched() {
        let oracle = Oracle {
            cve: "CVE-TEST".to_string(),
            slice: Some("test".to_string()),
            name: None,
            commit: None,
            ground_truth: vec![OracleEntry {
                file: "src/foo.c".to_string(),
                function: String::new(),
                line_start: 100,
                line_end: 100,
                cwe: vec!["CWE-78".to_string()],
                kind: String::new(),
                notes: String::new(),
                expected_verdict: None,
                expected_severity: None,
            }],
            expected_min_recall: None,
            notes: None,
        };
        let dump = FindingsDump {
            count: 1,
            findings: vec![finding_row(
                "src/foo.c",
                105,
                "XSS CWE-79 via reflected input",
            )],
        };
        let report = score(&cli(), &oracle, &dump, Path::new("/tmp"));
        assert_eq!(report.recall.pm_lines, 0.0);
        assert_eq!(report.recall.file_only, 1.0);
    }

    #[test]
    fn score_proof_state_breakdown_partitions_primary_hits() {
        let oracle = Oracle {
            cve: "CVE-TEST".to_string(),
            slice: Some("test".to_string()),
            name: None,
            commit: None,
            ground_truth: vec![
                OracleEntry {
                    file: "src/a.c".to_string(),
                    function: String::new(),
                    line_start: 10,
                    line_end: 10,
                    cwe: vec!["CWE-78".to_string()],
                    kind: String::new(),
                    notes: String::new(),
                    expected_verdict: None,
                    expected_severity: None,
                },
                OracleEntry {
                    file: "src/b.c".to_string(),
                    function: String::new(),
                    line_start: 20,
                    line_end: 20,
                    cwe: vec!["CWE-78".to_string()],
                    kind: String::new(),
                    notes: String::new(),
                    expected_verdict: None,
                    expected_severity: None,
                },
                OracleEntry {
                    file: "src/c.c".to_string(),
                    function: String::new(),
                    line_start: 30,
                    line_end: 30,
                    cwe: vec!["CWE-78".to_string()],
                    kind: String::new(),
                    notes: String::new(),
                    expected_verdict: None,
                    expected_severity: None,
                },
            ],
            expected_min_recall: None,
            notes: None,
        };
        let mut validated = finding_row("src/a.c", 10, "CWE-78 exec");
        validated.static_proof_state = Some("statically_confirmed".to_string());
        validated.vuln_source = Some("ainalysis".to_string());
        let mut other_static = finding_row("src/b.c", 20, "CWE-78 exec");
        other_static.static_proof_state = Some("signal_only".to_string());
        let llm_only = finding_row("src/c.c", 30, "CWE-78 exec");
        let dump = FindingsDump {
            count: 3,
            findings: vec![validated, other_static, llm_only],
        };
        let report = score(&cli(), &oracle, &dump, Path::new("/tmp"));
        assert_eq!(report.hits, 3);
        assert_eq!(report.proof_state_breakdown.validated, 1);
        assert_eq!(report.proof_state_breakdown.other_static, 1);
        assert_eq!(report.proof_state_breakdown.llm_only, 1);
        assert_eq!(report.vuln_source_breakdown.get("ainalysis"), Some(&1));
        assert_eq!(report.vuln_source_breakdown.get("unknown"), Some(&2));
    }

    #[test]
    fn score_reports_verdict_and_severity_label_accuracy() {
        let oracle = Oracle {
            cve: "CVE-TEST".to_string(),
            slice: Some("test".to_string()),
            name: None,
            commit: None,
            ground_truth: vec![
                OracleEntry {
                    file: "src/a.c".to_string(),
                    function: String::new(),
                    line_start: 10,
                    line_end: 10,
                    cwe: vec!["CWE-78".to_string()],
                    kind: String::new(),
                    notes: String::new(),
                    expected_verdict: Some("true_positive".to_string()),
                    expected_severity: Some("high".to_string()),
                },
                OracleEntry {
                    file: "src/b.c".to_string(),
                    function: String::new(),
                    line_start: 20,
                    line_end: 20,
                    cwe: vec!["CWE-79".to_string()],
                    kind: String::new(),
                    notes: String::new(),
                    expected_verdict: Some("false_positive".to_string()),
                    expected_severity: Some("medium".to_string()),
                },
            ],
            expected_min_recall: None,
            notes: None,
        };
        let mut correct = finding_row("src/a.c", 10, "CWE-78 exec");
        correct.severity = "ERROR".to_string();
        correct.triage = Some(FindingTriageRow {
            verdict: "tp".to_string(),
        });
        let mut wrong = finding_row("src/b.c", 20, "CWE-79 reflected");
        wrong.severity = "low".to_string();
        wrong.verdict = Some("true_positive".to_string());
        let dump = FindingsDump {
            count: 2,
            findings: vec![correct, wrong],
        };

        let report = score(&cli(), &oracle, &dump, Path::new("/tmp"));

        assert_eq!(report.label_accuracy.verdict_labeled, 2);
        assert_eq!(report.label_accuracy.verdict_correct, 1);
        assert_eq!(report.label_accuracy.verdict_accuracy, Some(0.5));
        assert_eq!(report.label_accuracy.severity_labeled, 2);
        assert_eq!(report.label_accuracy.severity_correct, 1);
        assert_eq!(report.label_accuracy.severity_accuracy, Some(0.5));
        assert_eq!(report.matches[0].verdict_match, Some(true));
        assert_eq!(report.matches[1].severity_match, Some(false));
    }
}
