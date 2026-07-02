use super::*;

use crate::findings::Severity;
use std::path::{Path, PathBuf};

pub(in crate::modules) fn run_network_security_config_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_network_security_start(ctx, &target);
    let outcome = match scan_network_security(&input, &target) {
        Ok(outcome) => outcome,
        Err(error) => {
            return Ok(failed_tool_output(
                "android-apk:network-security-config",
                &target,
                error,
            ))
        }
    };
    let persisted = persist_tool_findings(
        "android-apk",
        &target,
        &outcome.findings,
        ctx.workspace,
        ctx.findings_store,
    )?;
    emit_network_security_done(ctx, outcome.findings.len());
    Ok(network_security_output(&outcome, persisted))
}

struct NscScanOutcome {
    config_path: PathBuf,
    summary: NetworkSecuritySummary,
    findings: Vec<Finding>,
}

fn scan_network_security(input: &Value, workspace_root: &Path) -> Result<NscScanOutcome> {
    let config_path = resolve_config_path(input, workspace_root)?;
    let summary = parse_network_security_config(&config_path)?;
    let findings = network_security_findings(&summary, &config_path);
    Ok(NscScanOutcome {
        config_path,
        summary,
        findings,
    })
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, message: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, message.to_string()).emit();
    }
}

fn emit_network_security_start(ctx: &ToolExecutionContext<'_>, target: &Path) {
    emit_step(
        ctx,
        "tool",
        "scan",
        &format!(
            "network-security-config start · target={}",
            target.display()
        ),
    );
}

fn emit_network_security_done(ctx: &ToolExecutionContext<'_>, findings_count: usize) {
    emit_step(
        ctx,
        "done",
        "scan",
        &format!("network-security-config complete · {findings_count} findings"),
    );
}

fn resolve_config_path(input: &Value, workspace_root: &Path) -> Result<PathBuf> {
    if let Some(raw) = input
        .get("configPath")
        .or_else(|| input.get("config_path"))
        .and_then(Value::as_str)
    {
        let path = PathBuf::from(raw);
        if path.is_file() {
            return Ok(path);
        }
    }
    let candidate = workspace_root
        .join("android-decompiled")
        .join("apktool")
        .join("res")
        .join("xml")
        .join("network_security_config.xml");
    if !candidate.is_file() {
        anyhow::bail!(
            "android-apk:network-security-config: missing {}. Either the APK has no network security config or apktool decode hasn't run yet.",
            candidate.display()
        );
    }
    Ok(candidate)
}

pub(in crate::modules) fn network_security_findings(
    summary: &NetworkSecuritySummary,
    config_path: &Path,
) -> Vec<Finding> {
    let path = config_path.display().to_string();
    let mut findings = Vec::new();
    if summary.base_cleartext == Some(true) {
        findings.push(nsc_finding(
            "android-apk:nsc-base-cleartext",
            &path,
            Severity::High,
            "base-config sets cleartextTrafficPermitted=\"true\" (CWE-319). All non-domain-specific traffic may use HTTP.",
        ));
    }
    findings.extend(domain_findings(&summary.domain_configs, &path));
    if summary.trust_anchors_user && summary.debug_cleartext != Some(true) {
        findings.push(nsc_finding(
            "android-apk:nsc-user-ca",
            &path,
            Severity::Medium,
            "Production network-security-config trusts user-installed CAs (CWE-295). Attackers can MITM by installing a rogue CA on the device.",
        ));
    }
    findings
}

fn domain_findings(configs: &[DomainConfig], path: &str) -> Vec<Finding> {
    configs
        .iter()
        .filter_map(|config| domain_cleartext_finding(config, path))
        .collect()
}

fn domain_cleartext_finding(config: &DomainConfig, path: &str) -> Option<Finding> {
    if config.cleartext_permitted != Some(true) {
        return None;
    }
    Some(nsc_finding(
        "android-apk:nsc-domain-cleartext",
        path,
        Severity::High,
        &format!(
            "domain-config permits cleartext for {:?} (CWE-319). HTTP traffic to listed hosts is exempt from TLS.",
            config.domains
        ),
    ))
}

fn nsc_finding(rule_id: &str, file_path: &str, severity: Severity, message: &str) -> Finding {
    Finding::new_tool(
        "android-apk",
        rule_id,
        file_path,
        1,
        None,
        severity,
        message.to_string(),
    )
}

fn network_security_output(
    outcome: &NscScanOutcome,
    persisted: Option<GenericPersistedRun>,
) -> Value {
    let summary_text = format!(
        "android-apk:network-security-config: {} findings (domains={}, user-CA={})",
        outcome.findings.len(),
        outcome.summary.domain_configs.len(),
        outcome.summary.trust_anchors_user
    );
    json!({
        "ok": true,
        "summary": summary_text,
        "output": summary_text,
        "data": {
            "configPath": outcome.config_path.display().to_string(),
            "baseCleartext": outcome.summary.base_cleartext,
            "debugCleartext": outcome.summary.debug_cleartext,
            "trustAnchorsUser": outcome.summary.trust_anchors_user,
            "domainCount": outcome.summary.domain_configs.len(),
            "findings": outcome.findings,
            "persisted": persisted,
        },
        "warnings": [],
        "errors": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sample_summary() -> NetworkSecuritySummary {
        NetworkSecuritySummary {
            base_cleartext: Some(true),
            debug_cleartext: None,
            trust_anchors_user: true,
            domain_configs: vec![DomainConfig {
                domains: vec!["internal.example".into()],
                cleartext_permitted: Some(true),
                trust_anchors_user: false,
            }],
        }
    }

    #[test]
    fn findings_cover_base_cleartext_domain_and_user_ca() {
        let summary = sample_summary();
        let findings = network_security_findings(&summary, Path::new("nsc.xml"));
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"android-apk:nsc-base-cleartext"));
        assert!(ids.contains(&"android-apk:nsc-domain-cleartext"));
        assert!(ids.contains(&"android-apk:nsc-user-ca"));
    }

    #[test]
    fn user_ca_skipped_when_debug_cleartext_true() {
        let mut summary = sample_summary();
        summary.debug_cleartext = Some(true);
        let findings = network_security_findings(&summary, Path::new("nsc.xml"));
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(!ids.contains(&"android-apk:nsc-user-ca"));
    }

    #[test]
    fn domain_finding_includes_domain_name() {
        let summary = sample_summary();
        let findings = network_security_findings(&summary, Path::new("nsc.xml"));
        let domain = findings
            .iter()
            .find(|f| f.rule_id == "android-apk:nsc-domain-cleartext")
            .unwrap();
        assert!(domain.message.contains("internal.example"));
    }
}
