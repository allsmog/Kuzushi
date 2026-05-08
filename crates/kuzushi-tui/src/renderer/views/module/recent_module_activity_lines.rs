use super::*;

pub(crate) fn recent_module_activity_lines(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Vec<Line<'static>> {
    match module_id {
        "recon" => {
            if let Some(snapshot) = app.recon_snapshot.as_ref() {
                let lines = recon_snapshot_lines(snapshot, take);
                if !lines.is_empty() {
                    return lines;
                }
            }
        }
        "carlini-threat-hunt" => {
            if let Some(report) = app.carlini_snapshot.as_ref() {
                return carlini_snapshot_lines(report);
            }
        }
        "agentic-sast" => {
            if let Some(report) = app.agentic_sast_snapshot.as_ref() {
                return agentic_sast_snapshot_lines(report);
            }
        }
        _ => {}
    }

    // Fallback: existing log-grep path (brittle but unchanged from before
    // the snapshot caching was introduced).
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
    let mut lines: Vec<Line<'static>> = Vec::new();
    let host_label = |service: &kuzushi_core::ReconService| -> String {
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
    };

    if !snapshot.services.is_empty() {
        for service in snapshot.services.iter().take(take) {
            let host = host_label(service);
            let svc = service
                .name
                .clone()
                .unwrap_or_else(|| service.proto.clone());
            let banner = service
                .banner
                .clone()
                .unwrap_or_else(|| service.state.clone());
            lines.push(Line::from(vec![
                Span::styled(" ▸ ", theme::warn()),
                Span::styled(host, theme::primary()),
                Span::styled(":", theme::subtle()),
                Span::styled(format!("{}", service.port), theme::accent()),
                Span::raw("  "),
                Span::styled(pad(&svc, 14), theme::muted()),
                Span::styled(banner, theme::primary()),
            ]));
        }
    } else {
        for host in snapshot.hosts.iter().take(take) {
            let label = host
                .hostname
                .clone()
                .unwrap_or_else(|| host.address.clone());
            lines.push(Line::from(vec![
                Span::styled(" ▸ ", theme::warn()),
                Span::styled(label, theme::primary()),
                Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
                Span::styled(host.state.clone(), theme::muted()),
            ]));
        }
    }
    lines
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
