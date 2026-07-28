//! Mapping a member-resolved chain onto an ordinary open `Finding` with a
//! deterministic identity so re-proposals stay triage-idempotent.

use super::{Finding, MemberRef, ModelChain, Severity};

pub(super) fn model_chain_finding(chain: &ModelChain) -> Finding {
    let id = model_chain_identity(chain);
    let entry = &chain.members[0];
    Finding::new_tool(
        "chains",
        "chains/model",
        entry.file_path.clone(),
        entry.start_line,
        None,
        chain_severity(&chain.members),
        model_chain_message(chain, &id),
    )
    .with_dedup_key(format!("chain:{id}"))
    .with_source_signature(id)
}

/// Chain severity is the strongest member severity — the composition never
/// self-certifies above its constituents; the follow-up triage pass judges
/// the composed impact.
fn chain_severity(members: &[MemberRef]) -> Severity {
    members
        .iter()
        .map(|member| member.severity)
        .max_by_key(|severity| severity_rank(*severity))
        .unwrap_or(Severity::Unknown)
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

/// Deterministic identity over the ordered member fingerprints, so the same
/// composition re-proposed in a later hunt keeps its fingerprint and stays
/// triage-idempotent.
pub(super) fn model_chain_identity(chain: &ModelChain) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for member in &chain.members {
        hasher.update(member.fingerprint.as_bytes());
        hasher.update(b"|");
    }
    let digest = hasher.finalize();
    let hex: String = digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("AC-{hex}")
}

fn model_chain_message(chain: &ModelChain, id: &str) -> String {
    let mut lines = vec![format!("Attack chain {id}: {}", chain.title), String::new()];
    lines.push("Components:".to_string());
    for member in &chain.members {
        lines.push(format!(
            "- {} at {}:{} [finding {}]",
            member.title, member.file_path, member.start_line, member.fingerprint
        ));
    }
    lines.push(String::new());
    lines.push("Attack path:".to_string());
    for (index, step) in chain.attack_path.iter().enumerate() {
        lines.push(format!("{}. {}", index + 1, step));
    }
    push_labelled(&mut lines, "Cumulative impact", &chain.cumulative_impact);
    push_labelled(
        &mut lines,
        "Why this chain matters",
        &chain.why_this_chain_matters,
    );
    push_labelled(
        &mut lines,
        "Detection difficulty",
        &chain.detection_difficulty,
    );
    lines.push(String::new());
    lines.push(format!(
        "Members: {}",
        chain
            .members
            .iter()
            .map(|member| member.fingerprint.clone())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    lines.join("\n")
}

fn push_labelled(lines: &mut Vec<String>, label: &str, value: &str) {
    if !value.trim().is_empty() {
        lines.push(String::new());
        lines.push(format!("{label}: {}", value.trim()));
    }
}

#[cfg(test)]
mod tests {
    use super::super::validate::validate_chain_hunt_output;
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn confirmed(fingerprint: &str, title: &str, severity: Severity, path: &str) -> Finding {
        let mut finding = Finding::new_tool("agentic", "rule", path, 10, None, severity, title);
        finding.fingerprint = fingerprint.to_string();
        finding
    }

    #[test]
    fn valid_chain_maps_to_a_stable_open_finding() {
        let a = confirmed("fp-a", "Unauthenticated parser", Severity::High, "svc/a.c");
        let b = confirmed("fp-b", "Heap write primitive", Severity::Critical, "svc/b.c");
        let by_fp: BTreeMap<&str, &Finding> = [("fp-a", &a), ("fp-b", &b)].into_iter().collect();
        let output = json!({"chains": [
            {"title": "Parser to heap write", "members": ["fp-a", "fp-b"],
             "attack_path": ["parse attacker file", "trigger write"],
             "cumulative_impact": "remote code execution",
             "why_this_chain_matters": "pre-auth to RCE",
             "detection_difficulty": "low log surface"}
        ]});
        let hunted = validate_chain_hunt_output(output, 8, &by_fp).unwrap();
        assert_eq!(hunted.chains.len(), 1);

        let finding = model_chain_finding(&hunted.chains[0]);
        assert_eq!(finding.tool, "chains");
        assert_eq!(finding.rule_id, "chains/model");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.file_path, "svc/a.c");
        assert!(finding.message.contains("finding fp-a"));
        assert!(finding
            .message
            .contains("Cumulative impact: remote code execution"));
        // Same composition => same fingerprint (triage idempotence).
        let again = model_chain_finding(&hunted.chains[0]);
        assert_eq!(finding.fingerprint, again.fingerprint);
    }
}
