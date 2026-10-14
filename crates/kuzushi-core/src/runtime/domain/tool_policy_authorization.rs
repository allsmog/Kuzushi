use super::*;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub const READ_ONLY_ASK_POLICY_PROTOCOL_VERSION: u32 = 1;
pub const READ_ONLY_ASK_POLICY_ID: &str = "ask.concurrent-read-only.v1";
pub const READ_ONLY_ASK_TOOLS: [&str; 4] = ["Read", "LS", "Glob", "Grep"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentToolPolicyAuthorization {
    pub protocol_version: u32,
    pub policy_id: String,
    pub policy: AgentToolPolicy,
}

impl AgentToolPolicyAuthorization {
    pub fn for_scoped_policy(policy: &AgentToolPolicy) -> Result<Option<Self>> {
        if policy.read_scope.is_none() {
            anyhow::ensure!(
                policy.profile != READ_ONLY_SCOPE_POLICY_ID,
                "scoped policy omitted its read membership"
            );
            return Ok(None);
        }
        validate_scoped_policy(policy)?;
        Ok(Some(Self {
            protocol_version: READ_ONLY_ASK_POLICY_PROTOCOL_VERSION,
            policy_id: READ_ONLY_SCOPE_POLICY_ID.into(),
            policy: policy.clone(),
        }))
    }

    pub fn read_only_scope(root: &Path, scope: AgentReadScope) -> Result<Self> {
        scope.validate()?;
        let mut authorization = Self::read_only_ask(root)?;
        authorization.policy_id = READ_ONLY_SCOPE_POLICY_ID.into();
        authorization.policy.profile = READ_ONLY_SCOPE_POLICY_ID.into();
        authorization.policy.read_scope = Some(scope);
        Ok(authorization)
    }

    pub fn read_only_ask(root: &Path) -> Result<Self> {
        let canonical = std::fs::canonicalize(root)
            .with_context(|| format!("could not resolve Ask read root {}", root.display()))?;
        anyhow::ensure!(canonical.is_dir(), "Ask read root is not a directory");
        let mut policy = AgentToolPolicy::new(READ_ONLY_ASK_POLICY_ID, READ_ONLY_ASK_TOOLS);
        policy.mcp_read_roots = vec![canonical];
        Ok(Self {
            protocol_version: READ_ONLY_ASK_POLICY_PROTOCOL_VERSION,
            policy_id: READ_ONLY_ASK_POLICY_ID.to_string(),
            policy,
        })
    }
}

fn validate_scoped_policy(policy: &AgentToolPolicy) -> Result<()> {
    policy
        .read_scope
        .as_ref()
        .context("scoped policy omitted membership")?
        .validate()?;
    anyhow::ensure!(
        policy.profile == READ_ONLY_SCOPE_POLICY_ID,
        "read membership requires the scoped read-only profile"
    );
    anyhow::ensure!(
        policy.tools == READ_ONLY_ASK_TOOLS,
        "scoped policy requires the exact read-only tools"
    );
    anyhow::ensure!(
        !policy.mcps,
        "scoped read-only policy cannot mount MCP tools"
    );
    anyhow::ensure!(
        policy.mcps_attached.is_empty(),
        "scoped read-only policy cannot attach MCP tools"
    );
    anyhow::ensure!(
        policy.mcp_read_roots.len() == 1,
        "scoped read membership requires one root"
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentToolPolicyReceipt {
    pub protocol_version: u32,
    pub policy_id: String,
    pub effective_tools: Vec<String>,
    pub read_roots: Vec<PathBuf>,
    pub write_shell_tools_mounted: bool,
    pub mcp_tools_mounted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_scope_sha256: Option<String>,
}

impl AgentToolPolicyReceipt {
    pub fn validate_for(&self, authorization: &AgentToolPolicyAuthorization) -> Result<()> {
        let expected_scope = authorization
            .policy
            .read_scope
            .as_ref()
            .map(|scope| scope.sha256.clone());
        anyhow::ensure!(
            self.read_scope_sha256 == expected_scope,
            "bridge did not acknowledge the exact read membership"
        );
        anyhow::ensure!(
            self.protocol_version == authorization.protocol_version,
            "Ask bridge acknowledged an unsupported tool-policy protocol"
        );
        anyhow::ensure!(
            self.policy_id == authorization.policy_id,
            "Ask bridge acknowledged a different tool policy"
        );
        anyhow::ensure!(
            self.effective_tools == expected_tools(&authorization.policy),
            "Ask bridge effective tools differ from the authorized read-only set"
        );
        anyhow::ensure!(
            self.read_roots == authorization.policy.mcp_read_roots,
            "Ask bridge read roots differ from the authorized roots"
        );
        anyhow::ensure!(
            !self.write_shell_tools_mounted && !self.mcp_tools_mounted,
            "Ask bridge mounted a write, shell, or MCP tool"
        );
        Ok(())
    }
}

fn expected_tools(policy: &AgentToolPolicy) -> Vec<String> {
    policy.tools.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_ask_authorization_is_exact_and_canonical() {
        let target = tempfile::tempdir().unwrap();
        let authorization = AgentToolPolicyAuthorization::read_only_ask(target.path()).unwrap();

        assert_eq!(authorization.policy_id, READ_ONLY_ASK_POLICY_ID);
        assert_eq!(authorization.policy.tools, READ_ONLY_ASK_TOOLS);
        assert!(!authorization.policy.mcps);
        assert!(authorization.policy.mcps_attached.is_empty());
        assert_eq!(
            authorization.policy.mcp_read_roots,
            vec![target.path().canonicalize().unwrap()]
        );
    }

    #[test]
    fn receipt_validation_fails_closed_on_missing_authority() {
        let target = tempfile::tempdir().unwrap();
        let authorization = AgentToolPolicyAuthorization::read_only_ask(target.path()).unwrap();
        let receipt = AgentToolPolicyReceipt {
            protocol_version: authorization.protocol_version,
            policy_id: authorization.policy_id.clone(),
            effective_tools: vec!["Read".to_string()],
            read_roots: authorization.policy.mcp_read_roots.clone(),
            write_shell_tools_mounted: false,
            mcp_tools_mounted: false,
            read_scope_sha256: None,
        };

        assert!(receipt.validate_for(&authorization).is_err());
    }
}
