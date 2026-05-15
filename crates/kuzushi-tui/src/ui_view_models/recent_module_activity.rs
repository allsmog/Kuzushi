use crate::{LogLine, ReconSnapshot, ShellApp};
use kuzushi_core::{AgenticSastReport, CarliniThreatHuntReport, ReconService, Severity};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ModuleActivityModel {
    pub(crate) rows: Vec<ModuleActivityRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ModuleActivityRow {
    Transcript {
        prefix: String,
        body: String,
    },
    ReconService {
        host: String,
        port: u16,
        service: String,
        banner: String,
    },
    ReconHost {
        label: String,
        state: String,
    },
    Finding {
        severity: Severity,
        rule_id: String,
        location: String,
    },
}

pub(crate) fn recent_module_activity_model(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> ModuleActivityModel {
    ModuleActivityModel {
        rows: snapshot_activity_rows(app, module_id, take)
            .unwrap_or_else(|| recent_log_activity_rows(app, module_id, take)),
    }
}

fn snapshot_activity_rows(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Option<Vec<ModuleActivityRow>> {
    recon_activity_rows(app, module_id, take)
        .or_else(|| threat_hunt_activity_rows(app, module_id))
        .or_else(|| agentic_activity_rows(app, module_id))
}

fn recon_activity_rows(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Option<Vec<ModuleActivityRow>> {
    if module_id != "recon" {
        return None;
    }
    let snapshot = app.recon_snapshot.as_ref()?;
    let rows = recon_snapshot_rows(snapshot, take);
    (!rows.is_empty()).then_some(rows)
}

fn threat_hunt_activity_rows(app: &ShellApp, module_id: &str) -> Option<Vec<ModuleActivityRow>> {
    if module_id != "carlini-threat-hunt" && module_id != "offense-review" {
        return None;
    }
    app.carlini_snapshot.as_ref().map(carlini_snapshot_rows)
}

fn agentic_activity_rows(app: &ShellApp, module_id: &str) -> Option<Vec<ModuleActivityRow>> {
    if module_id != "agentic-sast" {
        return None;
    }
    app.agentic_sast_snapshot
        .as_ref()
        .map(agentic_sast_snapshot_rows)
}

fn recon_snapshot_rows(snapshot: &ReconSnapshot, take: usize) -> Vec<ModuleActivityRow> {
    if !snapshot.services.is_empty() {
        return recon_service_rows(snapshot, take);
    }
    recon_host_rows(snapshot, take)
}

fn recon_service_rows(snapshot: &ReconSnapshot, take: usize) -> Vec<ModuleActivityRow> {
    snapshot
        .services
        .iter()
        .take(take)
        .map(|service| ModuleActivityRow::ReconService {
            host: recon_service_host_label(snapshot, service),
            port: service.port,
            service: service
                .name
                .clone()
                .unwrap_or_else(|| service.proto.clone()),
            banner: service
                .banner
                .clone()
                .unwrap_or_else(|| service.state.clone()),
        })
        .collect()
}

fn recon_host_rows(snapshot: &ReconSnapshot, take: usize) -> Vec<ModuleActivityRow> {
    snapshot
        .hosts
        .iter()
        .take(take)
        .map(|host| ModuleActivityRow::ReconHost {
            label: host
                .hostname
                .clone()
                .unwrap_or_else(|| host.address.clone()),
            state: host.state.clone(),
        })
        .collect()
}

fn recon_service_host_label(snapshot: &ReconSnapshot, service: &ReconService) -> String {
    snapshot
        .hosts
        .iter()
        .find(|host| host.id == service.host_id)
        .map(|host| {
            host.hostname
                .clone()
                .unwrap_or_else(|| host.address.clone())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn carlini_snapshot_rows(report: &CarliniThreatHuntReport) -> Vec<ModuleActivityRow> {
    let mut rows = vec![
        transcript_row(
            "result",
            format!(
                "carlini-threat-hunt: {} finding{} from {} actor{} ({} run{})",
                report.count,
                plural_suffix(report.count),
                report.actors,
                plural_suffix(report.actors),
                report.actor_runs,
                plural_suffix(report.actor_runs),
            ),
        ),
        transcript_row("cost", format!("cost ${:.4}", report.cost_usd)),
    ];
    rows.extend(finding_rows(&report.findings));
    rows
}

fn agentic_sast_snapshot_rows(report: &AgenticSastReport) -> Vec<ModuleActivityRow> {
    let mut rows = vec![
        transcript_row(
            "result",
            format!(
                "agentic-sast: {} finding{} under {}",
                report.count,
                plural_suffix(report.count),
                report.target,
            ),
        ),
        transcript_row("cost", format!("cost ${:.4}", report.cost_usd)),
    ];
    rows.extend(finding_rows(&report.findings));
    rows
}

fn finding_rows(findings: &[kuzushi_core::Finding]) -> Vec<ModuleActivityRow> {
    findings
        .iter()
        .take(5)
        .map(|finding| ModuleActivityRow::Finding {
            severity: finding.severity,
            rule_id: finding.rule_id.clone(),
            location: format!("{}:{}", finding.file_path, finding.start_line),
        })
        .collect()
}

fn recent_log_activity_rows(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Vec<ModuleActivityRow> {
    let recent = recent_module_log(app, module_id, take);
    recent
        .into_iter()
        .flat_map(|(prefix, body)| split_transcript_body(prefix, body))
        .collect()
}

fn recent_module_log(app: &ShellApp, module_id: &str, take: usize) -> Vec<(String, String)> {
    let module_id = module_id.to_string();
    let mut matches = app
        .log
        .iter()
        .rev()
        .filter(|line| log_matches_module(line, &module_id))
        .take(take)
        .map(|line| (line.prefix.clone(), line.body.clone()))
        .collect::<Vec<_>>();
    matches.reverse();
    matches
}

fn log_matches_module(line: &LogLine, module_id: &str) -> bool {
    line.prefix == module_id
        || line.prefix.starts_with(&format!("{module_id}:"))
        || line.body.contains(&format!("{module_id}:"))
        || is_recon_tool_log(line, module_id)
}

fn is_recon_tool_log(line: &LogLine, module_id: &str) -> bool {
    module_id == "recon"
        && (line.prefix == "tool" || line.prefix == "result")
        && line.body.contains("recon")
}

fn split_transcript_body(prefix: String, body: String) -> Vec<ModuleActivityRow> {
    body.lines()
        .map(|line| transcript_row(&prefix, line.to_string()))
        .collect()
}

fn transcript_row(prefix: &str, body: String) -> ModuleActivityRow {
    ModuleActivityRow::Transcript {
        prefix: prefix.to_string(),
        body,
    }
}

fn plural_suffix(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests;
