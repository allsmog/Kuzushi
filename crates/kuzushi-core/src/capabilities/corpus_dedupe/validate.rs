//! Honesty gate for model-proposed duplicate groups. Free text is never a
//! matching input: every membership must resolve to a real candidate
//! fingerprint, groups stay within one file, and no fingerprint plays two
//! roles across the accepted set.

use super::{DuplicateGroup, Finding, JudgedGroups};
use anyhow::Result;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn validate_dedupe_output(
    value: Value,
    max_groups: usize,
    by_fingerprint: &BTreeMap<&str, &Finding>,
) -> Result<JudgedGroups> {
    let Some(items) = value.get("groups").and_then(Value::as_array) else {
        anyhow::bail!("triage:dedupe output must contain a `groups` array");
    };
    let mut gate = GroupGate::new(by_fingerprint);
    for item in items {
        gate.admit(item, max_groups);
    }
    Ok(JudgedGroups {
        groups: gate.groups,
        dropped: gate.dropped,
    })
}

struct GroupGate<'a> {
    by_fingerprint: &'a BTreeMap<&'a str, &'a Finding>,
    groups: Vec<DuplicateGroup>,
    dropped: BTreeMap<String, usize>,
    assigned_duplicates: BTreeSet<String>,
    canonicals: BTreeSet<String>,
}

impl<'a> GroupGate<'a> {
    fn new(by_fingerprint: &'a BTreeMap<&'a str, &'a Finding>) -> Self {
        Self {
            by_fingerprint,
            groups: Vec::new(),
            dropped: BTreeMap::new(),
            assigned_duplicates: BTreeSet::new(),
            canonicals: BTreeSet::new(),
        }
    }

    fn admit(&mut self, item: &Value, max_groups: usize) {
        let Some(group) = self.validated_group(item) else {
            return;
        };
        if self.groups.len() >= max_groups {
            self.drop("over_group_cap");
            return;
        }
        self.canonicals.insert(group.canonical_fingerprint.clone());
        self.assigned_duplicates
            .extend(group.duplicate_fingerprints.iter().cloned());
        self.groups.push(group);
    }

    fn validated_group(&mut self, item: &Value) -> Option<DuplicateGroup> {
        let canonical = nonempty_str(item, "canonical_fingerprint")?;
        let Some(canonical_finding) = self.by_fingerprint.get(canonical.as_str()) else {
            self.drop("hallucinated_canonical");
            return None;
        };
        if self.assigned_duplicates.contains(&canonical) {
            self.drop("canonical_is_duplicate");
            return None;
        }
        let canonical_path = canonical_finding.file_path.clone();
        let duplicates = self.validated_duplicates(item, &canonical, &canonical_path);
        if duplicates.is_empty() {
            self.drop("no_valid_members");
            return None;
        }
        Some(DuplicateGroup {
            canonical_fingerprint: canonical,
            duplicate_fingerprints: duplicates,
            root_cause_summary: nonempty_str(item, "root_cause_summary").unwrap_or_default(),
            confidence: item
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
        })
    }

    fn validated_duplicates(
        &mut self,
        item: &Value,
        canonical: &str,
        canonical_path: &str,
    ) -> Vec<String> {
        let proposed = item
            .get("duplicate_fingerprints")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut kept = Vec::new();
        for fingerprint in proposed {
            if let Some(reason) = self.member_rejection(&fingerprint, canonical, canonical_path) {
                self.drop(reason);
            } else if !kept.contains(&fingerprint) {
                kept.push(fingerprint);
            }
        }
        kept
    }

    fn member_rejection(
        &self,
        fingerprint: &str,
        canonical: &str,
        canonical_path: &str,
    ) -> Option<&'static str> {
        if fingerprint == canonical {
            return Some("canonical_in_duplicates");
        }
        let Some(finding) = self.by_fingerprint.get(fingerprint) else {
            return Some("hallucinated_member");
        };
        if finding.file_path != canonical_path {
            return Some("cross_file");
        }
        if self.assigned_duplicates.contains(fingerprint) || self.canonicals.contains(fingerprint) {
            return Some("double_membership");
        }
        None
    }

    fn drop(&mut self, reason: &str) {
        *self.dropped.entry(reason.to_string()).or_insert(0) += 1;
    }
}

fn nonempty_str(item: &Value, key: &str) -> Option<String> {
    item.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use serde_json::json;

    fn candidate(fingerprint: &str, path: &str) -> Finding {
        let mut finding =
            Finding::new_tool("agentic", "rule", path, 10, None, Severity::High, "title");
        finding.fingerprint = fingerprint.to_string();
        finding
    }

    fn index<'a>(findings: &'a [Finding]) -> BTreeMap<&'a str, &'a Finding> {
        findings
            .iter()
            .map(|finding| (finding.fingerprint.as_str(), finding))
            .collect()
    }

    fn group(canonical: &str, duplicates: &[&str], confidence: f64) -> Value {
        json!({
            "canonical_fingerprint": canonical,
            "duplicate_fingerprints": duplicates,
            "root_cause_summary": "same missing validation",
            "confidence": confidence,
        })
    }

    #[test]
    fn hallucinated_canonical_kills_the_group_and_members_are_pruned() {
        let findings = vec![candidate("fp-a", "src/a.py"), candidate("fp-b", "src/a.py")];
        let by_fp = index(&findings);
        let output = json!({"groups": [
            group("fp-ghost", &["fp-a"], 0.9),
            group("fp-a", &["fp-b", "fp-ghost2", "fp-a"], 0.9),
        ]});
        let judged = validate_dedupe_output(output, 16, &by_fp).unwrap();
        assert_eq!(judged.groups.len(), 1);
        assert_eq!(judged.groups[0].canonical_fingerprint, "fp-a");
        assert_eq!(judged.groups[0].duplicate_fingerprints, vec!["fp-b"]);
        assert_eq!(judged.dropped.get("hallucinated_canonical"), Some(&1));
        assert_eq!(judged.dropped.get("hallucinated_member"), Some(&1));
        assert_eq!(judged.dropped.get("canonical_in_duplicates"), Some(&1));
    }

    #[test]
    fn cross_file_members_and_double_membership_are_rejected() {
        let findings = vec![
            candidate("fp-a", "src/a.py"),
            candidate("fp-b", "src/a.py"),
            candidate("fp-c", "src/other.py"),
            candidate("fp-d", "src/a.py"),
        ];
        let by_fp = index(&findings);
        let output = json!({"groups": [
            group("fp-a", &["fp-b", "fp-c"], 0.9),
            group("fp-d", &["fp-b"], 0.9),
        ]});
        let judged = validate_dedupe_output(output, 16, &by_fp).unwrap();
        assert_eq!(judged.groups.len(), 1);
        assert_eq!(judged.dropped.get("cross_file"), Some(&1));
        assert_eq!(judged.dropped.get("double_membership"), Some(&1));
        assert_eq!(judged.dropped.get("no_valid_members"), Some(&1));
    }

    #[test]
    fn a_canonical_that_is_anothers_duplicate_is_rejected() {
        let findings = vec![
            candidate("fp-a", "src/a.py"),
            candidate("fp-b", "src/a.py"),
            candidate("fp-c", "src/a.py"),
        ];
        let by_fp = index(&findings);
        let output = json!({"groups": [
            group("fp-a", &["fp-b"], 0.9),
            group("fp-b", &["fp-c"], 0.9),
        ]});
        let judged = validate_dedupe_output(output, 16, &by_fp).unwrap();
        assert_eq!(judged.groups.len(), 1);
        assert_eq!(judged.dropped.get("canonical_is_duplicate"), Some(&1));
    }
}
