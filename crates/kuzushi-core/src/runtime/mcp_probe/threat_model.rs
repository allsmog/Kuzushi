use crate::capabilities::threat_model::{
    load_exact_threat_model, threat_model_object_path, ThreatModelSelection,
};
use crate::runtime::{AgentToolPolicy, McpAttachment};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

pub(crate) fn bind_selected_threat_model_attachment(
    mut policy: AgentToolPolicy, input: &Value, root: &Path,
) -> Result<AgentToolPolicy> {
    let selection = ThreatModelSelection::from_input(input)?;
    if !policy.mcps || !selection.is_bound() { return Ok(policy); }
    policy.mcps_attached.retain(|attachment| attachment.name != "threat-model");
    if let ThreatModelSelection::Revision(reference) = selection {
        load_exact_threat_model(root, &reference)?;
        let path = threat_model_object_path(root, &reference.sha256)?;
        policy.mcps_attached.push(McpAttachment::new("threat-model", path.display().to_string())
            .with_artifact_identity(reference.sha256));
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::threat_model::commit_test_model;
    use serde_json::json;

    #[test]
    fn bound_mcp_uses_selected_immutable_bytes_and_omission_removes_only_that_server() {
        let root = tempfile::tempdir().unwrap();
        let first = commit_test_model(root.path(), "ACCEPTED_ALPHA");
        commit_test_model(root.path(), "ACTIVE_BETA");
        let policy = AgentToolPolicy::default().try_with_mcps_for_target(root.path()).unwrap();
        let bound = bind_selected_threat_model_attachment(policy.clone(), &json!({"threatModelRef": first}), root.path()).unwrap();
        let attachment = bound.mcps_attached.iter().find(|value| value.name == "threat-model").unwrap();
        assert_eq!(attachment.artifact_identity.as_deref(), Some(first.sha256.as_str()));
        let body = std::fs::read_to_string(&attachment.artifact_path).unwrap();
        assert!(body.contains("ACCEPTED_ALPHA"));
        assert!(!body.contains("ACTIVE_BETA"));
        let omitted = bind_selected_threat_model_attachment(policy, &json!({"threatModelRef": null}), root.path()).unwrap();
        assert!(!omitted.mcps_attached.iter().any(|value| value.name == "threat-model"));
        assert!(omitted.mcps_attached.iter().any(|value| value.name == "treesitter"));
        let disabled = bind_selected_threat_model_attachment(AgentToolPolicy::default(), &json!({"threatModelRef": first}), root.path()).unwrap();
        assert!(!disabled.mcps);
    }
}
