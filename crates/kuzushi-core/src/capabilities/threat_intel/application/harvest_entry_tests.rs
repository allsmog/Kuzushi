use super::*;
use crate::capabilities::threat_intel::domain::HuntKind;

#[test]
fn maps_known_cwes_to_uaf_hunt_or_taint_iris_next() {
    assert_eq!(hunt_kind_for_cwe("CWE-416"), HuntKind::UafHunt);
    assert_eq!(hunt_kind_for_cwe("CWE-415"), HuntKind::UafHunt);
    assert_eq!(hunt_kind_for_cwe("CWE-367"), HuntKind::UafHunt);
    assert_eq!(hunt_kind_for_cwe("CWE-190"), HuntKind::TaintIrisNext);
    assert_eq!(hunt_kind_for_cwe("CWE-79"), HuntKind::TaintIrisNext);
    assert_eq!(hunt_kind_for_cwe("CWE-122"), HuntKind::TaintIrisNext);
}

#[test]
fn catalog_entry_from_pattern_picks_first_cwe_and_routes_uaf_to_uaf_hunt() {
    let record = serde_json::json!({
        "id": "CVE-2025-49844",
        "description": "Use-after-free in Lua client lifecycle.",
        "severity": "CRITICAL",
    });
    let pattern = serde_json::json!({
        "cwe": ["CWE-416"],
        "languages": ["c"],
        "vulnerableShape": "freed pointer dereferenced after freeClient",
        "fixShape": "guard with client->flags",
        "detectionQuery": "freeClient.*client->",
        "keywords": ["freeClient", "lua_client"],
        "description": "Lua client UAF",
        "confidence": "HIGH",
    });
    let entry = catalog_entry_from_pattern("CVE-2025-49844", record, pattern);
    assert_eq!(entry.cwe, "CWE-416");
    assert_eq!(entry.hunt, HuntKind::UafHunt);
    assert_eq!(entry.severity, "critical");
    assert_eq!(entry.id, "redis-cve-2025-49844");
    assert_eq!(entry.languages, vec!["c"]);
    assert!(!entry.source_signals.is_empty());
    assert!(!entry.structural_queries.is_empty());
}
