//! Keep cross-run finding history out of discovery's attached toolsets.
use crate::runtime::AgentToolPolicy;

pub(super) fn fresh_discovery_policy(mut policy: AgentToolPolicy) -> AgentToolPolicy {
    policy
        .mcps_attached
        .retain(|attachment| attachment.name != "findings");
    policy.mcps = policy.mcps && !policy.mcps_attached.is_empty();
    policy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::McpAttachment;

    #[test]
    fn discovery_removes_history_and_preserves_selected_source_context_tools() {
        let before = AgentToolPolicy::new("owned-read-policy", ["read_file"]).with_mcps_plan(vec![
            McpAttachment::constant("treesitter"),
            McpAttachment::constant("findings"),
            McpAttachment::constant("threat-model"),
        ]);
        let after = fresh_discovery_policy(before.clone());
        assert_eq!(
            after
                .mcps_attached
                .iter()
                .map(|attachment| attachment.name.as_str())
                .collect::<Vec<_>>(),
            vec!["treesitter", "threat-model"]
        );
        assert_eq!(after.profile, before.profile);
        assert_eq!(after.tools, before.tools);
        assert_eq!(after.read_scope, before.read_scope);
        assert_eq!(after.mcp_read_roots, before.mcp_read_roots);
        assert!(after.mcps);
    }

    #[test]
    fn removing_the_only_attachment_cannot_enable_the_legacy_mcp_fallback() {
        let policy =
            AgentToolPolicy::default().with_mcps_plan(vec![McpAttachment::constant("findings")]);
        let policy = fresh_discovery_policy(policy);
        assert!(policy.mcps_attached.is_empty());
        assert!(!policy.mcps);
        assert!(!fresh_discovery_policy(AgentToolPolicy::default()).mcps);
    }

    #[test]
    fn a_real_repository_with_an_existing_ledger_cannot_advertise_history_to_discovery() {
        use super::super::run_agentic_sast_report::AgenticSastRun;
        use crate::{FindingStore, ToolExecutionContext, V2Config, WorkspaceTarget};
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("hello.rs"), "// Owned inert source\n").unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let mut config = V2Config::default();
        config.model = Some("openai-codex:gpt-5.5".into());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let before = crate::proof::agent_tool_policy_for_input_and_target(
            &serde_json::json!({}),
            root.path(),
        )
        .unwrap();
        assert!(before
            .mcps_attached
            .iter()
            .any(|attachment| attachment.name == "findings"));
        let run = AgenticSastRun::from_input(&serde_json::json!({}), &ctx).unwrap();
        assert!(!run
            .tool_policy
            .mcps_attached
            .iter()
            .any(|attachment| attachment.name == "findings"));
        assert!(!run
            .enrichment
            .attached_mcps
            .iter()
            .any(|name| name == "findings"));
        assert_eq!(run.model, "openai-codex:gpt-5.5");
    }
}
