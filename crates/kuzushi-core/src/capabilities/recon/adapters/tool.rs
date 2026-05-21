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
        other => anyhow::bail!("unknown recon tool {other:?}"),
    }
}
