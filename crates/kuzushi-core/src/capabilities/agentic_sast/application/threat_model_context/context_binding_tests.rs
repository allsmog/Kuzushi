use super::*;
use crate::capabilities::campaign::capture_batch_equivalence;

#[test]
fn changed_supporting_context_cannot_remain_batch_equivalent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "fn main() { println!(\"hello\"); }\n",
    )
    .unwrap();
    let tree = crate::incremental_index::current_workspace_tree_hash(root.path()).unwrap();
    let path = crate::context::context_snapshot_path(root.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let config = crate::V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let input = json!({"taskMode":"manual","tasks":["agentic"],"threatModelRef":null,"triage":false,"verify":false,"autoPatch":false});
    let mut captures = Vec::new();
    for note in ["Labeled architecture A", "Labeled architecture B"] {
        let snapshot = json!({"target":root.path(),"provenance":{"treeHash":tree},"enrichedContext":{"architecturalNotes":[{"note":note}]}});
        assert!(crate::context::context_snapshot_freshness(root.path(), &snapshot).is_current());
        std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let prompt =
            PromptEnrichment::for_run(root.path(), &AgentToolPolicy::default(), &input).unwrap();
        let equivalence =
            capture_batch_equivalence(root.path(), &input, &config, &registry).unwrap();
        captures.push((prompt.context_enrichment.unwrap(), equivalence.sha256));
    }
    assert_ne!(
        captures[0].0, captures[1].0,
        "Actual scanner context must change in this fixture"
    );
    assert_ne!(
        captures[0].1, captures[1].1,
        "Changed supporting context must not masquerade as identical study conditions"
    );
}
