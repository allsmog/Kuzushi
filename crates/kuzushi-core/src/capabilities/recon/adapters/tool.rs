use super::*;

impl ReconReport {
    pub(crate) fn output(&self) -> String {
        match self.tool.as_str() {
            "recon:nmap" => format!(
                "recon:nmap discovered {} host{} and {} open service{} for {}",
                self.hosts.len(),
                plural(self.hosts.len()),
                self.services.len(),
                plural(self.services.len()),
                self.target
            ),
            "recon:subdomain" => format!(
                "recon:subdomain discovered {} subdomain{} for {}",
                self.subdomains.len(),
                plural(self.subdomains.len()),
                self.target
            ),
            "recon:http-fingerprint" => {
                let service = self
                    .services
                    .first()
                    .map(|service| {
                        format!(
                            "{}:{}",
                            service.name.as_deref().unwrap_or("http"),
                            service.port
                        )
                    })
                    .unwrap_or_else(|| "http".to_string());
                format!(
                    "recon:http-fingerprint registered {} as {service}",
                    self.target
                )
            }
            _ => format!("{} completed for {}", self.tool, self.target),
        }
    }

    pub(crate) fn to_tool_json(&self) -> Value {
        let output = self.output();
        crate::module_result::completed_output_result(output.clone(), output, json!(self))
    }
}

pub fn execute_recon_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    enforce_recon_scope(name, &input, ctx)?;
    match name {
        "recon:nmap" => ctx
            .with_cancellation(|cancel| run_recon_nmap(&input, ctx, cancel))
            .map(|report| report.to_tool_json()),
        "recon:subdomain" => ctx
            .with_cancellation(|cancel| run_recon_subdomain(&input, ctx, cancel))
            .map(|report| report.to_tool_json()),
        "recon:http-fingerprint" => ctx
            .with_cancellation(|cancel| run_recon_http_fingerprint(&input, ctx, cancel))
            .map(|report| report.to_tool_json()),
        "recon:import" => dispatch_recon_import(&input, ctx),
        other => anyhow::bail!("unknown recon tool {other:?}"),
    }
}

/// Dispatch a `recon:import` call to the per-source adapter. The input
/// carries `{"tool": "amass|httpx|nuclei|nmap-xml|burp-xml|har", "path": "..."}`.
/// Splitting by `tool` keeps the adapters focused (one parser per
/// supported recon format) while presenting a single dispatch verb.
fn dispatch_recon_import(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let kind = input
        .get("tool")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "recon:import needs a `tool` field. \
                 Supported: amass, httpx, nuclei, nmap-xml, burp-xml, har"
            )
        })?;
    match kind {
        "amass" => crate::capabilities::recon::application::run_recon_import_amass(input, ctx)
            .map(|report| report.to_tool_json()),
        "httpx" => crate::capabilities::recon::application::run_recon_import_httpx(input, ctx)
            .map(|report| report.to_tool_json()),
        "nuclei" => crate::capabilities::recon::application::run_recon_import_nuclei(input, ctx)
            .map(|report| report.to_tool_json()),
        "nmap-xml" | "nmap_xml" => {
            crate::capabilities::recon::application::run_recon_import_nmap_xml(input, ctx)
                .map(|report| report.to_tool_json())
        }
        "burp-xml" | "burp_xml" | "burp" => import_bounty_capture(input, ctx, false),
        "har" => import_bounty_capture(input, ctx, true),
        other => anyhow::bail!(
            "unknown recon:import tool {other:?}. \
             Supported: amass, httpx, nuclei, nmap-xml, burp-xml, har"
        ),
    }
}

fn import_bounty_capture(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    is_har: bool,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("recon:import requires an active workspace target")?;
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .context("recon:import needs a `path` field")?;
    if is_har {
        let summary = crate::findings::import::import_har(workspace, &path)?;
        return Ok(import_capture_output("har", summary.imported, summary.skipped_out_of_scope, summary));
    }
    let summary = crate::findings::import::import_burp_xml(workspace, &path)?;
    Ok(import_capture_output(
        "burp-xml",
        summary.imported,
        summary.skipped_out_of_scope,
        summary,
    ))
}

fn import_capture_output(
    format: &str,
    imported: usize,
    skipped_out_of_scope: usize,
    summary: impl serde::Serialize,
) -> Value {
    let skipped = if skipped_out_of_scope == 0 {
        String::new()
    } else {
        format!(" · {skipped_out_of_scope} out-of-scope skipped")
    };
    let output = format!("recon:import {format} imported {imported} finding(s){skipped}");
    crate::module_result::completed_output_result(output.clone(), output, json!(summary))
}

/// Refuse recon dispatch when the requested target is out of scope per
/// `.kuzushi/scope.toml`. Unknown verdicts are allowed only when the scope
/// has no in-scope allow list; absence of a match in allow-list mode refuses.
/// Absence of scope.toml is the no-op default.
fn enforce_recon_scope(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let Some(workspace) = ctx.workspace else {
        return Ok(());
    };
    let Some(scope) =
        crate::workspace::load_program_scope(workspace).context("Could not load scope.toml")?
    else {
        return Ok(());
    };
    let Some(target) = recon_target_field(input) else {
        return Ok(());
    };
    if scope.verdict(target) == crate::workspace::ScopeVerdict::OutOfScope {
        anyhow::bail!(
            "{name} refused: target {target:?} is out of scope per .kuzushi/scope.toml. \
             Update the file's [in_scope] or [out_of_scope] lists if this is wrong."
        );
    }
    Ok(())
}

/// Recon tools name their target field differently (`target`, `domain`,
/// `host`, `url`). Walk the common keys in priority order and return the
/// first non-empty value so the scope gate works uniformly across them.
fn recon_target_field(input: &Value) -> Option<&str> {
    for key in ["target", "domain", "host", "url"] {
        if let Some(value) = input
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(value);
        }
    }
    None
}
