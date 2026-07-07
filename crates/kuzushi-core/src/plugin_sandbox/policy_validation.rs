use super::{EnvPolicy, NetworkPolicy, PluginSandboxInvocation, SandboxPolicy, SubprocessPolicy};
use anyhow::{bail, Result};

pub(super) fn validate_invocation_policy(invocation: &PluginSandboxInvocation) -> Result<()> {
    require_command(&invocation.command)?;
    validate_sandbox_policy(&invocation.policy)
}

pub(super) fn validate_sandbox_policy(policy: &SandboxPolicy) -> Result<()> {
    deny_workspace_writes(policy.write_workspace)?;
    deny_network(policy.network)?;
    deny_environment(policy.env)?;
    deny_subprocess(policy.subprocess)
}

fn require_command(command: &[String]) -> Result<()> {
    if command.is_empty() {
        bail!("plugin sandbox command cannot be empty");
    }
    Ok(())
}

fn deny_workspace_writes(write_workspace: bool) -> Result<()> {
    if write_workspace {
        bail!("plugin sandbox policy cannot grant workspace writes");
    }
    Ok(())
}

fn deny_network(network: NetworkPolicy) -> Result<()> {
    if network != NetworkPolicy::None {
        bail!("plugin sandbox policy cannot grant ambient network access");
    }
    Ok(())
}

fn deny_environment(env: EnvPolicy) -> Result<()> {
    if env != EnvPolicy::None {
        bail!("plugin sandbox policy cannot inherit ambient environment");
    }
    Ok(())
}

fn deny_subprocess(subprocess: SubprocessPolicy) -> Result<()> {
    if subprocess != SubprocessPolicy::None {
        bail!("plugin sandbox policy cannot grant subprocess capability");
    }
    Ok(())
}
