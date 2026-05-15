use super::*;

pub(crate) fn dfd_canonical_lines() -> Vec<Line<'static>> {
    vec![
        dfd_top_border(),
        dfd_names_row(),
        dfd_details_row(),
        dfd_mid_border(),
        dfd_flow_labels(),
        dfd_flow_arrows(),
        dfd_worker_top_border(),
        dfd_worker_names_row(),
        dfd_worker_details_row(),
        dfd_worker_bottom_border(),
    ]
}

fn dfd_top_border() -> Line<'static> {
    let sub = theme::subtle();
    Line::from(vec![
        Span::raw("     "),
        Span::styled(
            "┌────────────┐         ┌─────────────┐         ┌──────────────┐",
            sub,
        ),
    ])
}

fn dfd_names_row() -> Line<'static> {
    let sub = theme::subtle();
    let acc = theme::accent();
    Line::from(vec![
        Span::raw("     "),
        Span::styled("│ ", sub),
        Span::styled("  user    ", acc),
        Span::styled("│  https  │ ", sub),
        Span::styled(" api edge  ", acc),
        Span::styled("│   sql   │ ", sub),
        Span::styled("  postgres   ", acc),
        Span::styled("│", sub),
    ])
}

fn dfd_details_row() -> Line<'static> {
    let sub = theme::subtle();
    let mut_ = theme::muted();
    Line::from(vec![
        Span::raw("     "),
        Span::styled("│ ", sub),
        Span::styled("  browser ", mut_),
        Span::styled("│ ──────► │ ", sub),
        Span::styled("  nginx    ", mut_),
        Span::styled("│ ──────► │ ", sub),
        Span::styled("  primary db ", mut_),
        Span::styled("│", sub),
    ])
}

fn dfd_mid_border() -> Line<'static> {
    let sub = theme::subtle();
    Line::from(vec![
        Span::raw("     "),
        Span::styled(
            "└────────────┘         └──────┬──────┘         └──────┬───────┘",
            sub,
        ),
    ])
}

fn dfd_flow_labels() -> Line<'static> {
    let sub = theme::subtle();
    let mut_ = theme::muted();
    let warn = theme::warn();
    Line::from(vec![
        Span::raw("                                       "),
        Span::styled("│ ", sub),
        Span::styled("jwt", mut_),
        Span::raw("                    "),
        Span::styled("│ ", sub),
        Span::styled("plaintext PII", warn),
    ])
}

fn dfd_flow_arrows() -> Line<'static> {
    let sub = theme::subtle();
    Line::from(vec![
        Span::raw("                                       "),
        Span::styled("▼", sub),
        Span::raw("                       "),
        Span::styled("▼", sub),
    ])
}

fn dfd_worker_top_border() -> Line<'static> {
    let sub = theme::subtle();
    Line::from(vec![
        Span::raw("                              "),
        Span::styled("┌──────────────┐         ┌──────────────┐", sub),
    ])
}

fn dfd_worker_names_row() -> Line<'static> {
    let sub = theme::subtle();
    let acc = theme::accent();
    Line::from(vec![
        Span::raw("                              "),
        Span::styled("│ ", sub),
        Span::styled(" worker pool  ", acc),
        Span::styled("│  amqp   │ ", sub),
        Span::styled(" s3 (us-east) ", acc),
        Span::styled("│", sub),
    ])
}

fn dfd_worker_details_row() -> Line<'static> {
    let sub = theme::subtle();
    let mut_ = theme::muted();
    Line::from(vec![
        Span::raw("                              "),
        Span::styled("│ ", sub),
        Span::styled(" rabbitmq cli ", mut_),
        Span::styled("│ ──────► │ ", sub),
        Span::styled(" invoices/    ", mut_),
        Span::styled("│", sub),
    ])
}

fn dfd_worker_bottom_border() -> Line<'static> {
    let sub = theme::subtle();
    Line::from(vec![
        Span::raw("                              "),
        Span::styled("└──────────────┘         └──────────────┘", sub),
    ])
}
