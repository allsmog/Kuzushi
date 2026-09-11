use super::*;
use super::import_nmap_xml_parse::{parse_nmap_xml, ParsedNmapHost, ParsedNmapService};

const TOOL: &str = "recon:import-nmap-xml";

/// Import an Nmap XML scan (`nmap -oX out.xml`) into the recon store as
/// `ReconHost` + `ReconService` rows. Parsed in-process via `quick-xml`
/// — no `nmap` binary required to ingest. Skips a host when its status
/// is not `up`, skips services that are not in the `open` state (P2
/// review), and skips hosts outside `.kuzushi/scope.toml` (P1 review),
/// disclosing that count in the report and its output line.
pub(crate) fn run_recon_import_nmap_xml(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ReconReport> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message("recon:import"))?;
    let path = required_path(input, "path", "recon:import nmap-xml needs a `path` field")?;
    let xml = crate::bounded_file::read_utf8_text(&path, 64 * 1024 * 1024)
        .with_context(|| format!("Could not read {}", path.display()))?;
    let parsed = parse_nmap_xml(&xml)
        .with_context(|| format!("Could not parse nmap XML at {}", path.display()))?;
    let mut context = ReconImportContext::open(workspace)?;
    for nmap_host in parsed.hosts {
        persist_nmap_host(&mut context, nmap_host)?;
    }
    context.into_report(TOOL, path.display().to_string())
}

fn persist_nmap_host(
    context: &mut ReconImportContext<'_>,
    nmap_host: ParsedNmapHost,
) -> Result<()> {
    if nmap_host.state != "up" {
        return Ok(());
    }
    if !host_in_scope(context, &nmap_host) {
        return Ok(());
    }
    let host = upsert_nmap_host(context, &nmap_host)?;
    push_open_services(context, &host.id, nmap_host.services)?;
    context.hosts.push(host);
    Ok(())
}

fn host_in_scope(context: &mut ReconImportContext<'_>, nmap_host: &ParsedNmapHost) -> bool {
    if let Some(hostname) = nmap_host.hostname.as_deref() {
        if !context.admit_host(hostname) {
            return false;
        }
    }
    context.admit_host(&nmap_host.address)
}

fn upsert_nmap_host(
    context: &mut ReconImportContext<'_>,
    nmap_host: &ParsedNmapHost,
) -> Result<ReconHost> {
    context.store.upsert_host(
        &context.workspace_id,
        &nmap_host.address,
        nmap_host.hostname.as_deref(),
        "alive",
        json!({
            "discoveredBy": TOOL,
            "discoveredAt": now_isoish(),
            "nmapState": nmap_host.state,
        }),
    )
}

fn push_open_services(
    context: &mut ReconImportContext<'_>,
    host_id: &str,
    services: Vec<ParsedNmapService>,
) -> Result<()> {
    for service in services {
        // P2 review: nmap XML carries closed/filtered ports alongside
        // open ones. Importing them pollutes the recon view, so keep
        // only the open services.
        if service.state != "open" {
            continue;
        }
        let recorded = context.store.upsert_service(
            host_id,
            service.port,
            &service.proto,
            service.name.as_deref(),
            service.product.as_deref(),
            &service.state,
            json!({
                "version": service.version,
                "raw": service.raw,
            }),
        )?;
        context.services.push(recorded);
    }
    Ok(())
}
