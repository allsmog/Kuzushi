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
                "recon:subdomain observed {} historical name{} for {}; liveness was not tested",
                self.subdomains.len(),
                plural(self.subdomains.len()),
                self.target
            ),
            "recon:http-fingerprint" => self.http_fingerprint_output(),
            _ => self.completion_output(),
        }
    }

    /// What a fingerprint run registered, named as the endpoint that answered
    /// rather than as the target that was asked for: a redirect moves the
    /// response, and the row in the recon store belongs to whoever sent it.
    fn http_fingerprint_output(&self) -> String {
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
        let subject = self.fingerprinted_url().unwrap_or(&self.target);
        format!(
            "recon:http-fingerprint registered {subject} as {service}{}",
            self.redirect_disclosure()
        )
    }

    /// The URL whose response the fingerprint describes, named only when it is
    /// not the requested target.
    fn fingerprinted_url(&self) -> Option<&str> {
        let redirects = self.redirects.as_ref()?;
        redirects
            .followed_from()
            .and_then(|_| redirects.fetched.last().map(String::as_str))
    }

    /// The redirects a fingerprint run followed and the one it declined. Silent
    /// for a run that met none.
    fn redirect_disclosure(&self) -> String {
        let Some(redirects) = self.redirects.as_ref() else {
            return String::new();
        };
        let followed = redirects.followed_from().map(|from| {
            let hops = redirects.hops();
            format!("followed {hops} redirect{} from {from}", plural(hops))
        });
        let declined = redirects.not_followed.as_ref().map(|declined| {
            format!(
                "redirect to {} not followed: {}",
                declined.url,
                declined.reason.phrase()
            )
        });
        [followed, declined]
            .into_iter()
            .flatten()
            .map(|phrase| format!(" · {phrase}"))
            .collect()
    }

    /// The line a verb outside the three scan verbs above completes with. For a
    /// `recon:import` adapter that is what it put in the recon store and what
    /// the scope gate or parser refused on the way. A tool name this cannot
    /// place keeps the old wording.
    fn completion_output(&self) -> String {
        let Some(source) = self.tool.strip_prefix("recon:import-") else {
            return format!("{} completed for {}", self.tool, self.target);
        };
        let out_of_scope = self.skipped_out_of_scope.unwrap_or_default();
        let unusable = self.skipped_unusable().unwrap_or_default();
        let skipped = recon_import_skip_phrase(out_of_scope, unusable)
            .map(|phrase| format!(" · {phrase}"))
            .unwrap_or_default();
        format!(
            "recon:import {source} imported {} from {}{skipped}",
            self.imported_rows(),
            self.target
        )
    }

    /// Parsed JSONL importers persist one summary note using the report's tool
    /// id. Read the unusable-row count from that note rather than inventing a
    /// second counter that can drift from the persisted import receipt. Older
    /// reports and import formats without such a receipt remain `None`.
    fn skipped_unusable(&self) -> Option<usize> {
        self.notes
            .iter()
            .rev()
            .find(|note| note.ntype == self.tool)
            .and_then(|note| note.data.get("skippedUnusable"))
            .and_then(Value::as_u64)
            .and_then(|count| usize::try_from(count).ok())
    }

    /// The rows an import landed, named in a stable order and only when it
    /// landed any. An import that persisted nothing says so rather than
    /// listing three zeroes.
    fn imported_rows(&self) -> String {
        let named: Vec<String> = [
            (self.hosts.len(), "host"),
            (self.services.len(), "service"),
            (self.notes.len(), "note"),
        ]
        .into_iter()
        .filter(|(count, _)| *count > 0)
        .map(|(count, noun)| format!("{count} {noun}{}", plural(count)))
        .collect();
        match named.is_empty() {
            true => "nothing".to_string(),
            false => named.join(", "),
        }
    }

    pub(crate) fn to_tool_json(&self) -> Value {
        let output = self.output();
        let mut data = json!(self);
        if let (Some(object), Some(unusable)) = (data.as_object_mut(), self.skipped_unusable()) {
            object.insert("skippedUnusable".to_string(), json!(unusable));
        }
        if matches!(
            self.tool.as_str(),
            "recon:nmap" | "recon:subdomain" | "recon:http-fingerprint"
        ) {
            data["coverage"] = json!({"complete":false});
            data["sourceVerified"] = json!(false);
            return crate::module_result::partial_output_result(
                format!("External observations: {} host{}, {} service{}; source claims and coverage require review",self.hosts.len(),plural(self.hosts.len()),self.services.len(),plural(self.services.len())),
                format!("External context observations. No repository coverage or source accuracy is established.\n{output}"),
                vec![json!({"code":"external-observations","message":"Reported hosts/services/technologies remain context claims. Passive names do not establish liveness. This action does not complete repository Map or Scan."})],data);
        }
        crate::module_result::completed_output_result(output.clone(), output, data)
    }
}

/// Say why a native recon JSONL import did not persist parsed records. Scope
/// refusals and records without an addressable host are distinct operator
/// facts, so keep both in stable order and remain silent only for a complete
/// import.
fn recon_import_skip_phrase(out_of_scope: usize, unusable: usize) -> Option<String> {
    let mut reasons = Vec::new();
    if out_of_scope > 0 {
        reasons.push(format!("{out_of_scope} out-of-scope"));
    }
    if unusable > 0 {
        reasons.push(format!("{unusable} without a usable host"));
    }
    (!reasons.is_empty()).then(|| format!("{} skipped", reasons.join(", ")))
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
fn dispatch_recon_import(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
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
    let path = super::required_path(input, "path", "recon:import needs a `path` field")?;
    if is_har {
        let summary = crate::findings::import::import_har(workspace, &path)?;
        let counts = CaptureImportCounts {
            imported: summary.imported,
            out_of_scope: summary.skipped_out_of_scope,
            unusable: summary.skipped_unusable,
        };
        return Ok(import_capture_output("har", counts, summary));
    }
    let summary = crate::findings::import::import_burp_xml(workspace, &path)?;
    let counts = CaptureImportCounts {
        imported: summary.imported,
        out_of_scope: summary.skipped_out_of_scope,
        unusable: summary.skipped_unusable,
    };
    Ok(import_capture_output("burp-xml", counts, summary))
}

/// What one capture import did with the entries it read.
struct CaptureImportCounts {
    imported: usize,
    out_of_scope: usize,
    unusable: usize,
}

fn import_capture_output(
    format: &str,
    counts: CaptureImportCounts,
    summary: impl serde::Serialize,
) -> Value {
    let skipped =
        crate::findings::import::capture_skip_phrase(counts.out_of_scope, counts.unusable)
            .map(|phrase| format!(" · {phrase}"))
            .unwrap_or_default();
    let imported = counts.imported;
    let output = format!("recon:import {format} imported {imported} finding(s){skipped}");
    crate::module_result::completed_output_result(output.clone(), output, json!(summary))
}

/// Refuse recon dispatch when the requested target is out of scope per
/// `.kuzushi/scope.toml`. Unknown verdicts are allowed only when the scope
/// has no in-scope allow list; absence of a match in allow-list mode refuses.
/// Absence of scope.toml is the no-op default.
fn enforce_recon_scope(name: &str, input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<()> {
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
    if scope.verdict_for(target, recon_target_syntax(name))
        == crate::workspace::ScopeVerdict::OutOfScope
    {
        anyhow::bail!(
            "{name} refused: target {target:?} is out of scope per .kuzushi/scope.toml. \
             Update the file's [in_scope] or [out_of_scope] lists if this is wrong."
        );
    }
    Ok(())
}

/// How a recon verb reads its target. `recon:nmap` hands the string to a
/// scanner whose target specification names a whole address block, so the gate
/// has to weigh every address in it. Every other verb hands the string to curl
/// or an importer, which resolve `10.0.0.1-2` as a domain name reaching
/// whatever DNS answers with — reading it as a block there would admit an asset
/// no rule covers.
fn recon_target_syntax(name: &str) -> crate::workspace::TargetSyntax {
    match name {
        "recon:nmap" => crate::workspace::TargetSyntax::AddressBlock,
        _ => crate::workspace::TargetSyntax::Host,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::recon::domain::{ReconNote, ReconPersisted};
    use std::collections::BTreeMap;

    #[test]
    fn native_recon_skip_phrase_names_each_drop_class() {
        assert_eq!(recon_import_skip_phrase(0, 0), None);
        assert_eq!(
            recon_import_skip_phrase(2, 0).as_deref(),
            Some("2 out-of-scope skipped")
        );
        assert_eq!(
            recon_import_skip_phrase(0, 3).as_deref(),
            Some("3 without a usable host skipped")
        );
        assert_eq!(
            recon_import_skip_phrase(2, 3).as_deref(),
            Some("2 out-of-scope, 3 without a usable host skipped")
        );
    }

    #[test]
    fn parsed_unusable_rows_reach_output_and_machine_data() {
        let report = ReconReport {
            tool: "recon:import-amass".to_string(),
            target: "/tmp/amass.jsonl".to_string(),
            hosts: Vec::new(),
            services: Vec::new(),
            notes: vec![ReconNote {
                id: "note-1".to_string(),
                workspace_id: "workspace-1".to_string(),
                host_id: None,
                service_id: None,
                ntype: "recon:import-amass".to_string(),
                data: json!({
                    "records": 3,
                    "count": 0,
                    "skippedOutOfScope": 1,
                    "skippedUnusable": 2,
                }),
            }],
            persisted: ReconPersisted {
                workspace_id: "workspace-1".to_string(),
                db: "/tmp/findings.sqlite3".to_string(),
                host_count: 0,
                service_count: 0,
            },
            skipped_out_of_scope: Some(1),
            subdomains: Vec::new(),
            fingerprint: BTreeMap::new(),
            redirects: None,
        };

        let output = report.output();
        assert!(output.contains("1 out-of-scope, 2 without a usable host skipped"));
        let result = report.to_tool_json();
        assert_eq!(result["data"]["skippedUnusable"], 2);
    }
}
