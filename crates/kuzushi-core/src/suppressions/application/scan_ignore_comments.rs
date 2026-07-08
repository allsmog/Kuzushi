use crate::findings::Finding;
use crate::suppressions::domain::{
    FindingRef, SuppressionOrigin, SuppressionPredicate, SuppressionReason, SuppressionRule,
};
use std::collections::BTreeMap;
use std::path::Path;

const MARKER: &str = "kuzushi-ignore:";

/// Result of scanning source for `# kuzushi-ignore:` comments: synthetic
/// suppression rules plus `path:line: message` diagnostics for malformed
/// comments (which suppress nothing — a silent misparse would violate the
/// no-silent-fallback rule).
pub struct IgnoreCommentScan {
    pub rules: Vec<SuppressionRule>,
    pub malformed: Vec<String>,
}

/// Scan the source files that carry findings for in-source ignore comments.
/// Semgrep `nosemgrep` semantics: the finding is still emitted/listed; a match
/// only produces a synthetic rule marking it suppressed. A comment on the
/// finding's start line, or the line directly above it, matches.
///
/// IO is bounded to files that already have findings: one read per distinct
/// path, cached for the call.
pub fn scan_ignore_comments(workspace_root: &Path, findings: &[Finding]) -> IgnoreCommentScan {
    let mut cache: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut rules = Vec::new();
    let mut malformed = Vec::new();
    for finding in findings {
        if finding.file_path.is_empty() || finding.start_line == 0 {
            continue;
        }
        let lines = file_lines(workspace_root, &finding.file_path, &mut cache);
        scan_finding(finding, lines, &mut rules, &mut malformed);
    }
    IgnoreCommentScan { rules, malformed }
}

fn file_lines<'a>(
    root: &Path,
    relative: &str,
    cache: &'a mut BTreeMap<String, Vec<String>>,
) -> &'a [String] {
    cache
        .entry(relative.to_string())
        .or_insert_with(|| read_lines(root, relative))
}

fn read_lines(root: &Path, relative: &str) -> Vec<String> {
    let path = root.join(relative);
    match std::fs::read_to_string(&path) {
        Ok(body) => body.lines().map(str::to_string).collect(),
        Err(_) => Vec::new(),
    }
}

fn scan_finding(
    finding: &Finding,
    lines: &[String],
    rules: &mut Vec<SuppressionRule>,
    malformed: &mut Vec<String>,
) {
    for line_number in candidate_line_numbers(finding.start_line) {
        let Some(text) = lines.get((line_number - 1) as usize) else {
            continue;
        };
        let Some(parsed) = parse_ignore_comment(text) else {
            continue;
        };
        match parsed {
            Ok(comment) => {
                if comment.targets(finding) {
                    rules.push(comment.into_rule(finding));
                    return;
                }
            }
            Err(message) => {
                malformed.push(format!("{}:{line_number}: {message}", finding.file_path));
            }
        }
    }
}

/// The finding's own line and the line above it.
fn candidate_line_numbers(start_line: u32) -> Vec<u32> {
    if start_line > 1 {
        vec![start_line, start_line - 1]
    } else {
        vec![start_line]
    }
}

struct ParsedIgnore {
    target: String,
    reason: SuppressionReason,
    statement: String,
}

impl ParsedIgnore {
    fn targets(&self, finding: &Finding) -> bool {
        if self.target == "*" {
            return true;
        }
        if self.target == finding.rule_id {
            return true;
        }
        FindingRef(self.target.clone()).matches(finding)
    }

    fn into_rule(self, finding: &Finding) -> SuppressionRule {
        SuppressionRule {
            id: format!("sup-comment-{}", finding.fingerprint),
            predicate: SuppressionPredicate {
                finding_id: Some(FindingRef(finding.fingerprint.clone())),
                ..SuppressionPredicate::empty()
            },
            reason: self.reason,
            statement: self.statement,
            actor: "in-source-comment".to_string(),
            created_at_unix: 0,
            expires_at_unix: None,
            origin: SuppressionOrigin::InSourceComment,
        }
    }
}

/// `None` → no `kuzushi-ignore:` marker on this line. `Some(Ok)` → a valid
/// directive. `Some(Err)` → a malformed directive (missing/unknown reason).
fn parse_ignore_comment(line: &str) -> Option<Result<ParsedIgnore, String>> {
    let start = line.find(MARKER)?;
    let rest = strip_trailing_block_comment(line[start + MARKER.len()..].trim());
    let mut tokens = rest.splitn(2, char::is_whitespace);
    let Some(target) = tokens.next().map(str::trim).filter(|value| !value.is_empty()) else {
        return Some(Err("kuzushi-ignore comment is missing a target".to_string()));
    };
    let remainder = tokens.next().map(strip_reason_separator).unwrap_or("");
    Some(parse_reason_and_statement(target, remainder))
}

fn parse_reason_and_statement(target: &str, remainder: &str) -> Result<ParsedIgnore, String> {
    let mut parts = remainder.splitn(2, char::is_whitespace);
    let reason_token = parts.next().map(str::trim).unwrap_or("");
    if reason_token.is_empty() {
        return Err(format!("kuzushi-ignore for {target:?} is missing a reason"));
    }
    let Some(reason) = SuppressionReason::parse(reason_token) else {
        return Err(format!("kuzushi-ignore reason {reason_token:?} is not recognized"));
    };
    let statement = parts
        .next()
        .map(strip_statement_separator)
        .filter(|value| !value.is_empty())
        .unwrap_or("in-source ignore comment")
        .to_string();
    Ok(ParsedIgnore {
        target: target.to_string(),
        reason,
        statement,
    })
}

/// Drop a leading em-dash / dash separator between target and reason.
fn strip_reason_separator(remainder: &str) -> &str {
    remainder
        .trim_start()
        .trim_start_matches(['—', '-'])
        .trim_start()
}

/// Drop a leading `:` separator between reason and statement.
fn strip_statement_separator(statement: &str) -> &str {
    statement.trim_start().trim_start_matches(':').trim()
}

fn strip_trailing_block_comment(text: &str) -> &str {
    text.trim_end().trim_end_matches("*/").trim_end()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, Severity};

    fn finding_at(fingerprint: &str, rule_id: &str, line: u32) -> Finding {
        Finding {
            fingerprint: fingerprint.to_string(),
            rule_id: rule_id.to_string(),
            file_path: "src/app.rs".to_string(),
            start_line: line,
            severity: Severity::High,
            ..Finding::default()
        }
    }

    #[test]
    fn wildcard_comment_above_line_matches() {
        let comment = parse_ignore_comment("    # kuzushi-ignore: * — false-positive : sanitized")
            .unwrap()
            .unwrap();
        assert_eq!(comment.target, "*");
        assert_eq!(comment.reason, SuppressionReason::FalsePositive);
        assert_eq!(comment.statement, "sanitized");
    }

    #[test]
    fn missing_reason_is_malformed() {
        let parsed = parse_ignore_comment("// kuzushi-ignore: rust.sqli").unwrap();
        assert!(parsed.is_err());
    }

    #[test]
    fn unknown_reason_is_malformed() {
        let parsed = parse_ignore_comment("# kuzushi-ignore: * — banana").unwrap();
        assert!(parsed.is_err());
    }

    #[test]
    fn non_marker_line_is_none() {
        assert!(parse_ignore_comment("let x = 1; // ordinary comment").is_none());
    }

    #[test]
    fn scan_matches_comment_on_line_above() {
        let lines = vec![
            "fn main() {".to_string(),
            "    // kuzushi-ignore: rust.sqli — used-in-tests".to_string(),
            "    run_query(input);".to_string(),
        ];
        let finding = finding_at("fp1", "rust.sqli", 3);
        let mut rules = Vec::new();
        let mut malformed = Vec::new();
        scan_finding(&finding, &lines, &mut rules, &mut malformed);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].reason, SuppressionReason::UsedInTests);
        assert_eq!(rules[0].origin, SuppressionOrigin::InSourceComment);
        assert!(malformed.is_empty());
    }

    #[test]
    fn scan_reports_malformed_and_suppresses_nothing() {
        let lines = vec!["// kuzushi-ignore: rust.sqli".to_string(), "code();".to_string()];
        let finding = finding_at("fp1", "rust.sqli", 2);
        let mut rules = Vec::new();
        let mut malformed = Vec::new();
        scan_finding(&finding, &lines, &mut rules, &mut malformed);
        assert!(rules.is_empty());
        assert_eq!(malformed.len(), 1);
        assert!(malformed[0].contains("src/app.rs:1"));
    }

    #[test]
    fn non_matching_target_does_not_suppress() {
        let lines = vec!["// kuzushi-ignore: other.rule — wont-fix".to_string(), "code();".to_string()];
        let finding = finding_at("fp1", "rust.sqli", 2);
        let mut rules = Vec::new();
        let mut malformed = Vec::new();
        scan_finding(&finding, &lines, &mut rules, &mut malformed);
        assert!(rules.is_empty());
        assert!(malformed.is_empty());
    }
}
