use super::{AttackSurfaceMap, AttackSurfaceSummary};
use anyhow::Result;
use std::path::Path;

/// Read the persisted attack-surface map back from the context snapshot.
///
/// Returns `Ok(None)` whenever the snapshot is absent, unreadable, or does not
/// carry a well-formed `attackSurfaceMap` — that is the honest "unranked, run
/// `context:build`" state, never an error. A truncated or malformed snapshot
/// must not fail the caller: deserialization failures also yield `Ok(None)`.
///
/// Tolerance is layered so one bad record never zeroes the whole map: an
/// unknown surface kind degrades to `AttackSurfaceKind::Unknown` (see the
/// `#[serde(other)]` variant), and a surface *record* that fails to parse falls
/// back to a summary-only map so density-only consumers (scan_recommender) stay
/// as resilient as the old summary-only parse.
pub fn load_attack_surface_map(root: &Path) -> Result<Option<AttackSurfaceMap>> {
    Ok(match load_attack_surface_map_detailed(root) {
        AttackSurfaceMapLoad::Full(map) | AttackSurfaceMapLoad::SummaryRecovered(map) => Some(map),
        AttackSurfaceMapLoad::Missing { .. } => None,
    })
}

/// The outcome of loading the persisted attack-surface map, distinguishing a
/// clean full parse from a summary-only recovery so honesty-sensitive callers
/// (e.g. `worklist:rank`) can tell a benign zero-surface map from a genuinely
/// degraded one.
pub enum AttackSurfaceMapLoad {
    /// The full `attackSurfaceMap` parsed cleanly. This includes a map that
    /// honestly carries zero surfaces (a benign/tiny repo), which must NOT be
    /// reported as degraded.
    Full(AttackSurfaceMap),
    /// The full parse failed (a malformed/truncated surface record), but the
    /// `summary` block recovered — surfaces are empty because the records were
    /// unreadable, not because none exist. This is the genuinely degraded state.
    SummaryRecovered(AttackSurfaceMap),
    /// No usable map. `file_present` is derived from the loader's own read
    /// attempt — never a separate `.exists()` stat that races the reader and
    /// follows symlinks differently: `true` means a snapshot file was actually
    /// read but yielded no readable attack-surface map (a legacy/foreign
    /// snapshot lacking the `attackSurfaceMap` key, or one the bounded reader
    /// could not decode), which honesty-sensitive callers surface as a
    /// `context:build` recovery hint. `false` means the snapshot was genuinely
    /// absent — the honest empty state.
    Missing { file_present: bool },
}

/// Load the persisted attack-surface map while preserving whether a summary-only
/// recovery fired. Existing `load_attack_surface_map` callers stay unchanged;
/// callers that must distinguish a benign empty map from a degraded recovery use
/// this variant.
pub fn load_attack_surface_map_detailed(root: &Path) -> AttackSurfaceMapLoad {
    match read_attack_surface_value(root) {
        SnapshotRead::Value(value) => parse_map_or_summary(value),
        SnapshotRead::PresentUnusable => AttackSurfaceMapLoad::Missing { file_present: true },
        SnapshotRead::Absent => AttackSurfaceMapLoad::Missing { file_present: false },
    }
}

fn parse_map_or_summary(value: serde_json::Value) -> AttackSurfaceMapLoad {
    if let Ok(map) = serde_json::from_value::<AttackSurfaceMap>(value.clone()) {
        return AttackSurfaceMapLoad::Full(map);
    }
    match summary_only_map(&value) {
        Some(map) => AttackSurfaceMapLoad::SummaryRecovered(map),
        // The snapshot file was read (the value came from it), so even a total
        // parse failure is a present-but-unreadable map, not an absent one.
        None => AttackSurfaceMapLoad::Missing { file_present: true },
    }
}

/// A full-map parse failed (e.g. a malformed surface record); recover the
/// `summary` alone so density-by-file survives, with no surfaces.
fn summary_only_map(value: &serde_json::Value) -> Option<AttackSurfaceMap> {
    let summary =
        serde_json::from_value::<AttackSurfaceSummary>(value.get("summary")?.clone()).ok()?;
    let root_name = value
        .get("rootName")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    Some(AttackSurfaceMap {
        root_name,
        surfaces: Vec::new(),
        summary,
    })
}

/// The result of attempting to read the persisted `attackSurfaceMap` value,
/// folding the presence signal into the single bounded read so no caller needs
/// a separate `.exists()` stat (which would race the loader and follow symlinks
/// differently than the `O_NOFOLLOW` reader).
enum SnapshotRead {
    /// The snapshot's `attackSurfaceMap` value was extracted.
    Value(serde_json::Value),
    /// A snapshot file was read but yielded no usable `attackSurfaceMap` value:
    /// the bounded read failed for a reason other than absence, the body was
    /// not valid JSON, or the `attackSurfaceMap` key is missing.
    PresentUnusable,
    /// No snapshot file exists at the expected path.
    Absent,
}

fn read_attack_surface_value(root: &Path) -> SnapshotRead {
    let path = crate::context::context_snapshot_path(root);
    let body = match crate::bounded_file::read_utf8_text_within(
        root,
        &path,
        crate::context::MAX_CONTEXT_SNAPSHOT_BYTES,
    ) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return SnapshotRead::Absent,
        // Any other read error (oversized, symlink refusal, non-file, decode
        // failure) means a snapshot path was present but unreadable.
        Err(_) => return SnapshotRead::PresentUnusable,
    };
    let Ok(snapshot) = serde_json::from_str::<serde_json::Value>(&body) else {
        return SnapshotRead::PresentUnusable;
    };
    match snapshot.get("attackSurfaceMap") {
        Some(value) => SnapshotRead::Value(value.clone()),
        None => SnapshotRead::PresentUnusable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::{
        AttackSurface, AttackSurfaceKind, AttackSurfaceRisk, AttackSurfaceSummary,
    };
    use std::collections::BTreeMap;

    fn write_snapshot(root: &Path, body: &str) {
        std::fs::create_dir_all(crate::workspace::workspace_state_root(root)).unwrap();
        std::fs::write(crate::context::context_snapshot_path(root), body).unwrap();
    }

    fn sample_map() -> AttackSurfaceMap {
        AttackSurfaceMap {
            root_name: "demo".to_string(),
            surfaces: vec![AttackSurface {
                id: "s1".to_string(),
                kind: AttackSurfaceKind::HttpRoute,
                path: "src/a.rs".to_string(),
                line: Some(4),
                language: "rust".to_string(),
                framework: None,
                title: "t".to_string(),
                evidence: "e".to_string(),
                method: None,
                route: None,
                boundary: None,
                risk: AttackSurfaceRisk {
                    rank: 1,
                    score: 92,
                    tier: "high".to_string(),
                    reasons: vec!["auth".to_string()],
                },
                metadata: serde_json::Value::Null,
            }],
            summary: AttackSurfaceSummary {
                total: 1,
                by_kind: BTreeMap::new(),
                by_file: BTreeMap::from([("src/a.rs".to_string(), 1)]),
                high_risk: 1,
                max_risk_score: 92,
                by_risk_tier: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn load_returns_none_without_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        assert!(load_attack_surface_map(temp.path()).unwrap().is_none());
    }

    #[test]
    fn load_round_trips_risk() {
        let temp = tempfile::tempdir().unwrap();
        let body = serde_json::json!({ "attackSurfaceMap": sample_map() }).to_string();
        write_snapshot(temp.path(), &body);

        let map = load_attack_surface_map(temp.path()).unwrap().unwrap();

        assert_eq!(map.surfaces[0].risk.score, 92);
        assert_eq!(map.surfaces[0].risk.tier, "high");
        assert_eq!(map.surfaces[0].risk.reasons, vec!["auth".to_string()]);
    }

    /// A malformed `attackSurfaceMap` (valid outer JSON, wrong inner shape) is
    /// the honest "no map" state, never an error — correction #6.
    #[test]
    fn load_is_none_on_truncated_map() {
        let temp = tempfile::tempdir().unwrap();
        write_snapshot(
            temp.path(),
            r#"{"attackSurfaceMap":{"rootName":"demo","surfaces":"oops"}}"#,
        );

        assert!(load_attack_surface_map(temp.path()).unwrap().is_none());
    }

    /// One surface kind emitted by a newer Kuzushi must not zero the map: the
    /// unknown kind degrades to `Unknown`, and every other surface plus the
    /// summary survives — F5.
    #[test]
    fn unknown_surface_kind_degrades_one_surface_not_the_map() {
        let temp = tempfile::tempdir().unwrap();
        write_snapshot(
            temp.path(),
            r#"{"attackSurfaceMap":{
                "rootName":"demo",
                "surfaces":[
                    {"id":"s1","kind":"http_route","path":"src/a.rs","line":4,
                     "language":"rust","title":"t","evidence":"e",
                     "risk":{"rank":1,"score":92,"tier":"high","reasons":["auth"]}},
                    {"id":"s2","kind":"quantum_surface","path":"src/b.rs","line":9,
                     "language":"rust","title":"u","evidence":"e2",
                     "risk":{"rank":2,"score":40,"tier":"medium","reasons":[]}}
                ],
                "summary":{"total":2,"byKind":{},"byFile":{"src/a.rs":1,"src/b.rs":1},
                           "highRisk":1,"maxRiskScore":92,"byRiskTier":{}}
            }}"#,
        );

        let map = load_attack_surface_map(temp.path()).unwrap().unwrap();

        assert_eq!(map.surfaces.len(), 2, "both surfaces survive");
        assert_eq!(map.surfaces[1].kind, AttackSurfaceKind::Unknown);
        assert_eq!(map.summary.total, 2);
        assert_eq!(map.summary.by_file.get("src/b.rs"), Some(&1));
    }

    /// A fully-parseable map that honestly carries zero surfaces is `Full`, NOT
    /// a summary recovery — the caller must be able to tell a benign empty map
    /// from a degraded one (C-1).
    #[test]
    fn empty_surface_map_loads_as_full_not_summary_recovered() {
        let temp = tempfile::tempdir().unwrap();
        write_snapshot(
            temp.path(),
            r#"{"attackSurfaceMap":{
                "rootName":"demo",
                "surfaces":[],
                "summary":{"total":0,"byKind":{},"byFile":{},
                           "highRisk":0,"maxRiskScore":0,"byRiskTier":{}}
            }}"#,
        );

        match load_attack_surface_map_detailed(temp.path()) {
            AttackSurfaceMapLoad::Full(map) => assert!(map.surfaces.is_empty()),
            other => panic!("expected Full(empty), got a different variant: {}", variant(&other)),
        }
    }

    /// A malformed surface record recovers a summary-only map and reports
    /// `SummaryRecovered`, distinct from a benign `Full`-empty map (C-1).
    #[test]
    fn malformed_surface_record_loads_as_summary_recovered() {
        let temp = tempfile::tempdir().unwrap();
        write_snapshot(
            temp.path(),
            r#"{"attackSurfaceMap":{
                "rootName":"demo",
                "surfaces":[{"kind":"http_route","oops":true}],
                "summary":{"total":2,"byKind":{},"byFile":{"src/a.rs":2},
                           "highRisk":0,"maxRiskScore":0,"byRiskTier":{}}
            }}"#,
        );

        match load_attack_surface_map_detailed(temp.path()) {
            AttackSurfaceMapLoad::SummaryRecovered(map) => {
                assert!(map.surfaces.is_empty());
                assert_eq!(map.summary.by_file.get("src/a.rs"), Some(&2));
            }
            other => panic!("expected SummaryRecovered, got {}", variant(&other)),
        }
    }

    #[test]
    fn detailed_load_is_missing_without_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        assert!(matches!(
            load_attack_surface_map_detailed(temp.path()),
            AttackSurfaceMapLoad::Missing {
                file_present: false
            }
        ));
    }

    /// A genuinely absent snapshot reports `file_present: false` so honesty-
    /// sensitive callers keep the "no map" empty state, driven off the loader's
    /// own read attempt rather than a separate `.exists()` stat.
    #[test]
    fn detailed_load_reports_absent_snapshot_as_not_present() {
        let temp = tempfile::tempdir().unwrap();
        assert!(matches!(
            load_attack_surface_map_detailed(temp.path()),
            AttackSurfaceMapLoad::Missing {
                file_present: false
            }
        ));
    }

    /// A snapshot file that was read but carries no readable attack-surface map
    /// (here: valid JSON with no `attackSurfaceMap` key) reports
    /// `file_present: true`, so the caller degrades instead of claiming absence.
    #[test]
    fn detailed_load_reports_present_but_unreadable_snapshot_as_present() {
        let temp = tempfile::tempdir().unwrap();
        write_snapshot(temp.path(), r#"{"unrelated":true}"#);
        assert!(matches!(
            load_attack_surface_map_detailed(temp.path()),
            AttackSurfaceMapLoad::Missing { file_present: true }
        ));

        // Invalid JSON is also a present-but-unreadable snapshot.
        write_snapshot(temp.path(), "{ not valid json");
        assert!(matches!(
            load_attack_surface_map_detailed(temp.path()),
            AttackSurfaceMapLoad::Missing { file_present: true }
        ));
    }

    fn variant(load: &AttackSurfaceMapLoad) -> &'static str {
        match load {
            AttackSurfaceMapLoad::Full(_) => "Full",
            AttackSurfaceMapLoad::SummaryRecovered(_) => "SummaryRecovered",
            AttackSurfaceMapLoad::Missing { .. } => "Missing",
        }
    }

    /// A surface *record* that cannot parse at all falls back to a summary-only
    /// map, so density-by-file consumers (scan_recommender) stay as lenient as
    /// the old summary-only parse — F5.
    #[test]
    fn malformed_surface_record_falls_back_to_summary_only() {
        let temp = tempfile::tempdir().unwrap();
        write_snapshot(
            temp.path(),
            r#"{"attackSurfaceMap":{
                "rootName":"demo",
                "surfaces":[{"kind":"http_route","oops":true}],
                "summary":{"total":2,"byKind":{},"byFile":{"src/a.rs":2},
                           "highRisk":0,"maxRiskScore":0,"byRiskTier":{}}
            }}"#,
        );

        let map = load_attack_surface_map(temp.path()).unwrap().unwrap();

        assert!(map.surfaces.is_empty(), "malformed surfaces dropped");
        assert_eq!(map.summary.by_file.get("src/a.rs"), Some(&2));
    }
}
