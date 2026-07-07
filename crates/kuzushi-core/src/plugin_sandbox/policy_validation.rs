use super::{EnvPolicy, NetworkPolicy, PluginSandboxInvocation, SandboxPolicy, SubprocessPolicy};
use anyhow::{bail, Result};

const MAX_MEMORY_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_FUEL_LIMIT: u64 = 1_000_000_000;
const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_BYTES_SERVED: u64 = 512 * 1024 * 1024;
const MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FIELD_BYTES: u64 = 256 * 1024;
const MAX_FINDINGS_RETURNED: u32 = 10_000;

pub(super) fn validate_invocation_policy(invocation: &PluginSandboxInvocation) -> Result<()> {
    require_command(&invocation.command)?;
    validate_sandbox_policy(&invocation.policy)
}

pub(super) fn validate_sandbox_policy(policy: &SandboxPolicy) -> Result<()> {
    deny_workspace_writes(policy.write_workspace)?;
    deny_network(policy.network)?;
    deny_environment(policy.env)?;
    deny_subprocess(policy.subprocess)?;
    require_bounded_limit(
        "memoryLimitBytes",
        policy.memory_limit_bytes,
        MAX_MEMORY_LIMIT_BYTES,
    )?;
    require_bounded_limit("fuelLimit", policy.fuel_limit, MAX_FUEL_LIMIT)?;
    require_bounded_limit("timeoutMs", policy.timeout_ms, MAX_TIMEOUT_MS)?;
    require_bounded_limit("maxBytesServed", policy.max_bytes_served, MAX_BYTES_SERVED)?;
    require_bounded_limit("maxOutputBytes", policy.max_output_bytes, MAX_OUTPUT_BYTES)?;
    require_bounded_limit("maxFieldBytes", policy.max_field_bytes, MAX_FIELD_BYTES)?;
    require_bounded_limit(
        "maxFindingsReturned",
        u64::from(policy.max_findings_returned),
        u64::from(MAX_FINDINGS_RETURNED),
    )?;
    Ok(())
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

fn require_bounded_limit(name: &str, value: u64, max: u64) -> Result<()> {
    if value == 0 {
        bail!("plugin sandbox policy {name} must be positive");
    }
    if value > max {
        bail!("plugin sandbox policy {name} must be <= {max}");
    }
    Ok(())
}
