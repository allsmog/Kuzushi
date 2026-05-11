use super::*;

pub(in crate::modules::taint_iris_next) fn summarize_taint_iris_next_triage(
    triage: &[Value],
) -> Value {
    let mut finding = 0usize;
    let mut candidate = 0usize;
    let mut rejected = 0usize;
    for item in triage {
        match item
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("candidate")
        {
            "finding" => finding += 1,
            "rejected" => rejected += 1,
            _ => candidate += 1,
        }
    }
    json!({
        "finding": finding,
        "candidate": candidate,
        "rejected": rejected,
    })
}

pub(in crate::modules::taint_iris_next) fn strongest_taint_iris_next_evidence_level(
    cwe: &str,
    evidence: &TaintIrisNextEvidenceResult,
) -> String {
    let mut strongest = "candidate";
    for item in &evidence.evidence {
        if item.cwe != cwe {
            continue;
        }
        if item.evidence_level == "path" {
            return "path".to_string();
        }
        if item.evidence_level == "linked" {
            strongest = "linked";
        }
    }
    strongest.to_string()
}

pub(in crate::modules::taint_iris_next) fn taint_iris_next_evidence_meets_minimum(
    level: &str,
    minimum: &str,
) -> bool {
    fn rank(value: &str) -> u8 {
        match value {
            "path" => 3,
            "linked" => 2,
            "candidate" => 1,
            _ => 0,
        }
    }
    rank(level) >= rank(minimum)
}

pub(in crate::modules::taint_iris_next) fn cwe_priority(cwe: &str) -> i32 {
    match cwe {
        "CWE-78" | "CWE-89" | "CWE-94" => 3,
        "CWE-22" | "CWE-79" | "CWE-502" | "CWE-611" | "CWE-918" => 2,
        _ => 1,
    }
}
