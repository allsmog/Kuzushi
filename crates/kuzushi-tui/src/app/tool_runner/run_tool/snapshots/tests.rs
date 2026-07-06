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
    assert!(app.taint_flow.is_none());
    assert!(app.exploit_chains.is_empty());

    app.hydrate_persisted_scene_snapshots(Some(dir.path()));

    assert_eq!(app.taint_flow.as_ref().expect("taint flow").cwe, "CWE-89");
    assert_eq!(app.exploit_chains.len(), 1);
    assert_eq!(app.exploit_chains[0].title, "SQLi");
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

    let flow = taint_flow_from_data(&data).expect("flow");

    assert_eq!(flow.stages.len(), MAX_TAINT_FLOW_STAGES);
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
