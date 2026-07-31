use super::*;
use kuzushi_core::V2Config;
use serde_json::json;

#[test]
fn hydrate_reloads_persisted_taint_and_exploit_snapshots() {
    let dir = tempfile::tempdir().expect("tempdir");
    kuzushi_core::capabilities::save_persistent_taint_flow(
        dir.path(),
        &json!({ "flows": [{
            "cwe": "CWE-89", "severity": "critical",
            "stages": [{ "message": "order_id", "filePath": "orders.rs", "line": 1 }]
        }] }),
    )
    .expect("save taint");
    kuzushi_core::capabilities::save_persistent_exploit_chains(
        dir.path(),
        &json!({ "chains": [{
            "id": "c1", "name": "SQLi", "overallSeverity": "critical",
            "steps": [{ "role": "source", "description": "unsanitised id",
                "filePath": "a.rs", "startLine": 2 }]
        }] }),
    )
    .expect("save chains");

    let mut app = ShellApp::new(V2Config::default(), None);
    assert!(app.domain().taint_flow().is_none());
    assert!(app.domain().exploit_chains().is_empty());

    app.hydrate_persisted_scene_snapshots(Some(dir.path()));

    assert_eq!(app.domain().taint_flow().expect("taint flow").cwe, "CWE-89");
    assert_eq!(app.domain().exploit_chains().len(), 1);
    assert_eq!(app.domain().exploit_chains()[0].title, "SQLi");
}

#[test]
fn exploit_chain_snapshots_are_capped() {
    let chains = (0..(MAX_EXPLOIT_CHAIN_SNAPSHOTS + 5))
        .map(|index| {
            json!({
                "id": format!("c{index}"),
                "name": format!("chain {index}"),
                "overallSeverity": "high",
                "preconditions": repeated_strings(MAX_EXPLOIT_CHAIN_PRECONDITIONS + 5),
                "steps": repeated_steps(MAX_EXPLOIT_CHAIN_STEPS + 5),
            })
        })
        .collect::<Vec<_>>();
    let data = json!({ "chains": chains });

    let aliases = exploit_chain_aliases(&data);
    let details = exploit_chain_details(&data);

    assert_eq!(aliases.len(), MAX_EXPLOIT_CHAIN_SNAPSHOTS);
    assert_eq!(details.len(), MAX_EXPLOIT_CHAIN_SNAPSHOTS);
    assert_eq!(details[0].steps.len(), MAX_EXPLOIT_CHAIN_STEPS);
    assert_eq!(
        details[0].preconditions.len(),
        MAX_EXPLOIT_CHAIN_PRECONDITIONS
    );
}

#[test]
fn taint_flow_snapshot_stages_are_capped() {
    let data = json!({
        "flows": [{
            "cwe": "CWE-79",
            "severity": "high",
            "stages": repeated_stages(MAX_TAINT_FLOW_STAGES + 5),
        }]
    });

    let flow = taint_flows_from_data(&data)
        .into_iter()
        .next()
        .expect("flow");

    assert_eq!(flow.stages.len(), MAX_TAINT_FLOW_STAGES);
}

#[test]
fn taint_flow_snapshots_preserve_all_finding_keys() {
    let data = json!({
        "flows": [
            {
                "findingFingerprint": "fp-first",
                "findingIdentityId": "fi_first",
                "stages": [{ "message": "first", "filePath": "src/shared.rs", "line": 1 }]
            },
            {
                "findingFingerprint": "fp-second",
                "findingIdentityId": "fi_second",
                "stages": [{ "message": "second", "filePath": "src/shared.rs", "line": 2 }]
            }
        ]
    });

    let flows = taint_flows_from_data(&data);

    assert_eq!(flows.len(), 2);
    assert_eq!(flows[0].finding_fingerprint.as_deref(), Some("fp-first"));
    assert_eq!(flows[1].finding_identity_id.as_deref(), Some("fi_second"));
}

fn repeated_strings(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("precondition {index}"))
        .collect()
}

fn repeated_steps(count: usize) -> Vec<serde_json::Value> {
    (0..count)
        .map(|index| {
            json!({
                "role": "hop",
                "description": format!("step {index}"),
                "filePath": "src/app.rs",
                "startLine": index + 1,
            })
        })
        .collect()
}

fn worklist_rank_result() -> serde_json::Value {
    json!({
        "data": {
            "rows": [{
                "path": "src/deep.rs", "line": 12, "score": 0.8, "rank": 1,
                "citations": [{
                    "contributor": "systemsHunt", "raw": 40.0, "rawDisplay": "score 40",
                    "normalized": 0.5, "normalization": "rank", "reasons": []
                }]
            }],
            "rankedTotal": 1,
            "contributors": {"systemsHunt": "live"},
            "unranked": [], "degraded": []
        }
    })
}

#[test]
fn worklist_rank_result_is_captured_into_app_state() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    assert!(app
        .domain()
        .worklist_snapshot_for(temp.path(), None)
        .is_none());

    app.cache_tool_snapshot("worklist:rank", &worklist_rank_result());

    let snapshot = app
        .domain()
        .worklist_snapshot_for(temp.path(), None)
        .expect("worklist captured");
    assert_eq!(snapshot["rows"][0]["path"], "src/deep.rs");
}

#[test]
fn worklist_snapshot_is_dropped_without_a_target() {
    // No engagement to render under: the capture is not stored, so no foreign
    // worklist can leak into a later target.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.cache_tool_snapshot("worklist:rank", &worklist_rank_result());
    assert!(app
        .domain()
        .worklist_snapshot_for(std::path::Path::new("/tmp/whatever"), None)
        .is_none());
}

#[test]
fn worklist_snapshot_does_not_render_under_a_different_target() {
    // New-1: capture on target A, then activate target B ⇒ A's rows must not
    // surface as B's worklist.
    let temp_a = tempfile::tempdir().expect("tempdir a");
    let temp_b = tempfile::tempdir().expect("tempdir b");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp_a.path().to_path_buf()));
    app.cache_tool_snapshot("worklist:rank", &worklist_rank_result());
    assert!(app
        .domain()
        .worklist_snapshot_for(temp_a.path(), None)
        .is_some());

    // The accessor is target-keyed, so B never sees A's capture even before a
    // full engagement reset clears it.
    app.set_target(Some(temp_b.path().to_path_buf()));
    assert!(app
        .domain()
        .worklist_snapshot_for(temp_b.path(), None)
        .is_none());
}

#[test]
fn worklist_snapshot_is_stale_when_attack_surface_rebuilds() {
    // New-1: a fresh context:build changes the attack-surface artifact version,
    // so the earlier capture no longer matches and the Read-safe fold wins.
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.domain_mut().set_worklist_snapshot(
        temp.path().to_path_buf(),
        Some(7),
        Some(worklist_rank_result()),
    );

    assert!(app
        .domain()
        .worklist_snapshot_for(temp.path(), Some(7))
        .is_some());
    assert!(
        app.domain()
            .worklist_snapshot_for(temp.path(), Some(9))
            .is_none(),
        "a rebuilt map (new artifact version) supersedes the capture"
    );
}

fn repeated_stages(count: usize) -> Vec<serde_json::Value> {
    (0..count)
        .map(|index| {
            json!({
                "message": format!("stage {index}"),
                "filePath": "src/app.rs",
                "line": index + 1,
            })
        })
        .collect()
}
