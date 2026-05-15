use super::*;

pub(crate) fn recent_module_activity_lines(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Vec<Line<'static>> {
    if let Some(lines) = recent_snapshot_activity_lines(app, module_id, take) {
        return lines;
    }
    recent_log_activity_lines(app, module_id, take)
}

fn recent_snapshot_activity_lines(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Option<Vec<Line<'static>>> {
    recon_activity_lines(app, module_id, take)
        .or_else(|| threat_hunt_activity_lines(app, module_id))
        .or_else(|| agentic_activity_lines(app, module_id))
}

fn recon_activity_lines(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Option<Vec<Line<'static>>> {
    if module_id != "recon" {
        return None;
    }
    let snapshot = app.recon_snapshot.as_ref()?;
    let lines = recon_snapshot_lines(snapshot, take);
    (!lines.is_empty()).then_some(lines)
}

fn threat_hunt_activity_lines(app: &ShellApp, module_id: &str) -> Option<Vec<Line<'static>>> {
    if module_id != "carlini-threat-hunt" && module_id != "offense-review" {
        return None;
    }
    app.carlini_snapshot.as_ref().map(carlini_snapshot_lines)
}

fn agentic_activity_lines(app: &ShellApp, module_id: &str) -> Option<Vec<Line<'static>>> {
    if module_id != "agentic-sast" {
        return None;
    }
    app.agentic_sast_snapshot
        .as_ref()
        .map(agentic_sast_snapshot_lines)
}

fn recent_log_activity_lines(app: &ShellApp, module_id: &str, take: usize) -> Vec<Line<'static>> {
    let recent = recent_module_log(app, module_id, take);
    let mut out = Vec::new();
    for (prefix, body) in &recent {
        for body_line in body.lines() {
            out.push(transcript_line(prefix, body_line, false));
        }
    }
    out
}

pub(crate) fn recon_snapshot_lines(
    snapshot: &crate::app::ReconSnapshot,
    take: usize,
) -> Vec<Line<'static>> {
    if !snapshot.services.is_empty() {
        return recon_service_lines(snapshot, take);
    }
    recon_host_lines(snapshot, take)
}

fn recon_service_lines(snapshot: &crate::app::ReconSnapshot, take: usize) -> Vec<Line<'static>> {
    snapshot
        .services
        .iter()
        .take(take)
        .map(|service| {
            let svc = service
                .name
                .clone()
                .unwrap_or_else(|| service.proto.clone());
            let banner = service
                .banner
                .clone()
                .unwrap_or_else(|| service.state.clone());
            Line::from(vec![
                Span::styled(" ▸ ", theme::warn()),
                Span::styled(
                    recon_service_host_label(snapshot, service),
                    theme::primary(),
                ),
                Span::styled(":", theme::subtle()),
                Span::styled(format!("{}", service.port), theme::accent()),
                Span::raw("  "),
                Span::styled(pad(&svc, 14), theme::muted()),
                Span::styled(banner, theme::primary()),
            ])
        })
        .collect()
}

fn recon_host_lines(snapshot: &crate::app::ReconSnapshot, take: usize) -> Vec<Line<'static>> {
    snapshot
        .hosts
        .iter()
        .take(take)
        .map(|host| {
            let label = host
                .hostname
                .clone()
                .unwrap_or_else(|| host.address.clone());
            Line::from(vec![
                Span::styled(" ▸ ", theme::warn()),
                Span::styled(label, theme::primary()),
                Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
                Span::styled(host.state.clone(), theme::muted()),
            ])
        })
        .collect()
}

fn recon_service_host_label(
    snapshot: &crate::app::ReconSnapshot,
    service: &kuzushi_core::ReconService,
) -> String {
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

pub(crate) fn transcript_finding_line(
    severity: Severity,
    rule_id: &str,
    file_path: &str,
    line: u32,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(" ▸ ", theme::warn()),
        Span::styled(
            format!("{:9}", severity.as_str().to_uppercase()),
            theme::severity(severity),
        ),
        Span::raw(" "),
        Span::styled(rule_id.to_string(), theme::accent()),
        Span::raw("  "),
        Span::styled(format!("{file_path}:{line}"), theme::muted()),
    ])
}
