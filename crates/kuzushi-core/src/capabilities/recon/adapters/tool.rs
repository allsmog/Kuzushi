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
        "recon:nmap" => {
            Ok(run_recon_nmap(&input, ctx, &ScanCancellation::default())?.to_tool_json())
        }
        "recon:subdomain" => {
            Ok(run_recon_subdomain(&input, ctx, &ScanCancellation::default())?.to_tool_json())
        }
        "recon:http-fingerprint" => {
            Ok(
                run_recon_http_fingerprint(&input, ctx, &ScanCancellation::default())?
                    .to_tool_json(),
            )
        }
        "recon:import" => Ok(dispatch_recon_import(&input, ctx)?.to_tool_json()),
        other => anyhow::bail!("unknown recon tool {other:?}"),
    }
}

/// Dispatch a `recon:import` call to the per-source adapter. The input
/// carries `{"tool": "amass|httpx|nuclei|nmap-xml", "path": "..."}`.
/// Splitting by `tool` keeps the adapters focused (one parser per
/// supported recon format) while presenting a single dispatch verb.
fn dispatch_recon_import(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<crate::capabilities::recon::domain::ReconReport> {
    let kind = input
        .get("tool")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "recon:import needs a `tool` field. \
                 Supported: amass, httpx, nuclei, nmap-xml"
            )
        })?;
    match kind {
        "amass" => crate::capabilities::recon::application::run_recon_import_amass(input, ctx),
        "httpx" => crate::capabilities::recon::application::run_recon_import_httpx(input, ctx),
        "nuclei" => crate::capabilities::recon::application::run_recon_import_nuclei(input, ctx),
        "nmap-xml" | "nmap_xml" => {
            crate::capabilities::recon::application::run_recon_import_nmap_xml(input, ctx)
        }
        other => anyhow::bail!(
            "unknown recon:import tool {other:?}. \
             Supported: amass, httpx, nuclei, nmap-xml"
        ),
    }
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
