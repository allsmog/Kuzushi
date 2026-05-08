use super::*;

pub(crate) fn dfd_canonical_lines() -> Vec<Line<'static>> {
    let sub = theme::subtle();
    let acc = theme::accent();
    let mut_ = theme::muted();
    let warn = theme::warn();
    vec![
        Line::from(vec![
            Span::raw("     "),
            Span::styled(
                "┌────────────┐         ┌─────────────┐         ┌──────────────┐",
                sub,
            ),
        ]),
        Line::from(vec![
            Span::raw("     "),
            Span::styled("│ ", sub),
            Span::styled("  user    ", acc),
            Span::styled("│  https  │ ", sub),
            Span::styled(" api edge  ", acc),
            Span::styled("│   sql   │ ", sub),
            Span::styled("  postgres   ", acc),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("     "),
            Span::styled("│ ", sub),
            Span::styled("  browser ", mut_),
            Span::styled("│ ──────► │ ", sub),
            Span::styled("  nginx    ", mut_),
            Span::styled("│ ──────► │ ", sub),
            Span::styled("  primary db ", mut_),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("     "),
            Span::styled(
                "└────────────┘         └──────┬──────┘         └──────┬───────┘",
                sub,
            ),
        ]),
        Line::from(vec![
            Span::raw("                                       "),
            Span::styled("│ ", sub),
            Span::styled("jwt", mut_),
            Span::raw("                    "),
            Span::styled("│ ", sub),
            Span::styled("plaintext PII", warn),
        ]),
        Line::from(vec![
            Span::raw("                                       "),
            Span::styled("▼", sub),
            Span::raw("                       "),
            Span::styled("▼", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("┌──────────────┐         ┌──────────────┐", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("│ ", sub),
            Span::styled(" worker pool  ", acc),
            Span::styled("│  amqp   │ ", sub),
            Span::styled(" s3 (us-east) ", acc),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("│ ", sub),
            Span::styled(" rabbitmq cli ", mut_),
            Span::styled("│ ──────► │ ", sub),
            Span::styled(" invoices/    ", mut_),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("└──────────────┘         └──────────────┘", sub),
        ]),
    ]
}

pub(crate) fn dfd_nodes_from_doc(doc: &serde_json::Value) -> Option<Vec<(String, String, String)>> {
    let nodes = doc.get("dfd")?.get("nodes")?.as_array()?;
    if nodes.is_empty() {
        return None;
    }
    let rows = nodes
        .iter()
        .filter_map(|n| {
            let id = n.get("id").and_then(|v| v.as_str())?.to_string();
            let node_type = n
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("node")
                .to_string();
            let zone = n
                .get("trustZone")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some((id, node_type, zone))
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        None
    } else {
        Some(rows)
    }
}
