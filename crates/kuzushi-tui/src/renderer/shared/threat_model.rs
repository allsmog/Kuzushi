use super::*;

pub(in crate::renderer) fn threat_nav(active: ThreatView) -> Line<'static> {
    let items = [
        (ThreatView::Dfd, "1 DFD"),
        (ThreatView::Stride, "2 STRIDE"),
        (ThreatView::Stories, "3 STORIES"),
        (ThreatView::Scope, "4 SCOPE"),
        (ThreatView::Summary, "5 SUMMARY"),
    ];
    let mut spans = Vec::new();
    for (index, (view, label)) in items.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("  ", theme::subtle()));
        }
        let style = if *view == active {
            theme::selection()
        } else {
            theme::muted()
        };
        spans.push(Span::styled(*label, style));
    }
    Line::from(spans)
}

pub(in crate::renderer) fn stride_row(
    letter: &str,
    severity: Severity,
    category: &str,
    count: usize,
    description: &str,
    width: u16,
) -> Line<'static> {
    let total = width as usize;
    let used = 3 + 3 + 1 + 16 + 4 + 10;
    let desc_w = total.saturating_sub(used).max(8);
    let issues_label = if count == 1 { "issue" } else { "issues" };
    let mut spans = vec![
        Span::raw("   "),
        Span::styled(format!(" {letter} "), theme::severity(severity)),
        Span::raw(" "),
        Span::styled(pad(category, 16), theme::muted()),
        Span::styled(format!("{count} "), theme::primary()),
        Span::styled(format!("{issues_label}"), theme::muted()),
    ];
    if !description.is_empty() {
        spans.push(Span::styled("  · ", theme::muted()));
        spans.push(Span::styled(fit(description, desc_w), theme::muted()));
    }
    Line::from(spans)
}

/// Returns the canonical 6-row STRIDE rollup matching the design fixture.
/// Used as a fallback when no `.kuzushi/threat-model.json` is present.
pub(in crate::renderer) fn stride_rollup_rows(
) -> Vec<(&'static str, Severity, &'static str, usize, String)> {
    vec![
        (
            "S",
            Severity::High,
            "Spoofing",
            2,
            "jwt without aud-claim, mailgun cname dangling".to_string(),
        ),
        (
            "T",
            Severity::Medium,
            "Tampering",
            1,
            "worker pool reads unsigned amqp messages".to_string(),
        ),
        ("R", Severity::Low, "Repudiation", 0, String::new()),
        (
            "I",
            Severity::Critical,
            "Info-disclosure",
            3,
            "plaintext PII at db→s3 boundary, debug logs".to_string(),
        ),
        (
            "D",
            Severity::Medium,
            "DoS",
            1,
            "no rate-limit on /checkout/confirm".to_string(),
        ),
        (
            "E",
            Severity::High,
            "Elev-of-priv",
            1,
            "admin subdomain shares jwt secret with api".to_string(),
        ),
    ]
}

/// Canonical 10-row ASCII DFD matching `design/mockups/threat-model.jsx`.
/// 5 boxed nodes + 2 annotated edges (jwt, plaintext PII).
pub(in crate::renderer) fn dfd_canonical_lines() -> Vec<Line<'static>> {
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

/// Extract `(id, node_type, trust_zone)` triples from `dfd.nodes` if present.
pub(in crate::renderer) fn dfd_nodes_from_doc(
    doc: &serde_json::Value,
) -> Option<Vec<(String, String, String)>> {
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

/// Try to load the persisted threat model for the active workspace target.
/// Returns `None` if the file doesn't exist or is empty/null.
pub(in crate::renderer) fn current_threat_model_doc(app: &ShellApp) -> Option<serde_json::Value> {
    let cwd = app
        .target
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let doc = kuzushi_core::load_persistent_threat_model(&cwd)?;
    if doc.is_null() {
        return None;
    }
    Some(doc)
}

/// Compute the STRIDE rollup from a persisted threat model document.
/// Returns `None` if the document has no `threats` array or it's empty.
pub(in crate::renderer) fn stride_rollup_from_doc(
    doc: &serde_json::Value,
) -> Option<Vec<(&'static str, Severity, &'static str, usize, String)>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let cats: [(&'static str, &'static str, &'static str); 6] = [
        ("S", "spoofing", "Spoofing"),
        ("T", "tampering", "Tampering"),
        ("R", "repudiation", "Repudiation"),
        ("I", "information-disclosure", "Info-disclosure"),
        ("D", "denial-of-service", "DoS"),
        ("E", "elevation-of-privilege", "Elev-of-priv"),
    ];
    let mut rows = Vec::with_capacity(6);
    for (letter, key, label) in cats {
        let matching: Vec<&serde_json::Value> = threats
            .iter()
            .filter(|t| {
                t.get("category")
                    .and_then(|c| c.as_str())
                    .map(|c| c.to_lowercase().replace('_', "-"))
                    .as_deref()
                    == Some(key)
            })
            .collect();
        let count = matching.len();
        let severity = matching
            .iter()
            .map(|t| {
                t.get("impact")
                    .and_then(|s| s.as_str())
                    .map(impact_to_severity)
                    .unwrap_or(Severity::Medium)
            })
            .max_by_key(|s| severity_rank(*s))
            .unwrap_or(Severity::Low);
        let description = matching
            .iter()
            .filter_map(|t| {
                t.get("title")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
            })
            .take(2)
            .collect::<Vec<_>>()
            .join(", ");
        rows.push((letter, severity, label, count, description));
    }
    Some(rows)
}

/// `(id, severity, title, attack_vector, location)` — one attacker story.
pub(in crate::renderer) type StoryRow = (String, Severity, String, String, String);

/// Extract attacker stories from the persisted threat model. Each `threats[]`
/// entry becomes one story, sorted by impact severity (highest first).
pub(in crate::renderer) fn stories_from_doc(doc: &serde_json::Value) -> Option<Vec<StoryRow>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let mut rows: Vec<StoryRow> = threats
        .iter()
        .filter_map(|t| {
            let id = t.get("id").and_then(|v| v.as_str())?.to_string();
            let severity = t
                .get("impact")
                .and_then(|v| v.as_str())
                .map(impact_to_severity)
                .unwrap_or(Severity::Medium);
            let title = t
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("untitled")
                .to_string();
            let attack = t
                .get("attackVector")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let location = t
                .get("affectedFiles")
                .and_then(|v| v.as_array())
                .and_then(|files| files.first())
                .map(|f| {
                    let path = f.get("filePath").and_then(|v| v.as_str()).unwrap_or("");
                    let line = f.get("startLine").and_then(|v| v.as_u64()).unwrap_or(0);
                    if path.is_empty() {
                        String::new()
                    } else if line == 0 {
                        path.to_string()
                    } else {
                        format!("{path}:{line}")
                    }
                })
                .unwrap_or_default();
            Some((id, severity, title, attack, location))
        })
        .collect();
    rows.sort_by_key(|(_, sev, _, _, _)| std::cmp::Reverse(severity_rank(*sev)));
    Some(rows)
}

/// Fixture matching the canonical 4 attacker stories used when no real
/// threat model is loaded.
pub(in crate::renderer) fn canonical_stories_fixture() -> Vec<StoryRow> {
    vec![
        (
            "T-001".to_string(),
            Severity::Critical,
            "sql injection via order_id concatenation".to_string(),
            "POST /orders/<id>".to_string(),
            "apps/api/orders.rs:142".to_string(),
        ),
        (
            "T-002".to_string(),
            Severity::Critical,
            "prompt injection sink reads user body".to_string(),
            "user message → llm context".to_string(),
            "apps/web/agents/concierge.ts:88".to_string(),
        ),
        (
            "T-003".to_string(),
            Severity::High,
            "jwt verify accepts alg=none".to_string(),
            "forged Authorization header".to_string(),
            "apps/api/auth/jwt.rs:54".to_string(),
        ),
        (
            "T-004".to_string(),
            Severity::High,
            "shell exec from cron payload".to_string(),
            "scheduled job pulls untrusted task".to_string(),
            "jobs/worker.py:213".to_string(),
        ),
    ]
}

/// `(severity, label, items)` — one criticality bucket of threat titles.
pub(in crate::renderer) type ScopeBucket = (Severity, &'static str, Vec<String>);

/// Bucket threats from the persisted model by impact severity.
pub(in crate::renderer) fn scope_buckets_from_doc(
    doc: &serde_json::Value,
) -> Option<Vec<ScopeBucket>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let mut buckets: Vec<ScopeBucket> = vec![
        (Severity::Critical, "critical", Vec::new()),
        (Severity::High, "high", Vec::new()),
        (Severity::Medium, "medium", Vec::new()),
        (Severity::Low, "low", Vec::new()),
    ];
    for t in threats {
        let severity = t
            .get("impact")
            .and_then(|v| v.as_str())
            .map(impact_to_severity)
            .unwrap_or(Severity::Medium);
        let title = t
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("untitled")
            .to_string();
        if let Some((_, _, items)) = buckets.iter_mut().find(|(sev, _, _)| *sev == severity) {
            items.push(title);
        }
    }
    Some(buckets)
}

/// Fixture used when no real threat model is loaded — matches the canonical
/// design content.
pub(in crate::renderer) fn canonical_scope_buckets() -> Vec<ScopeBucket> {
    vec![
        (
            Severity::Critical,
            "critical",
            vec![
                "sql injection via order_id concatenation".to_string(),
                "prompt injection sink reads user body".to_string(),
            ],
        ),
        (
            Severity::High,
            "high",
            vec![
                "jwt verify accepts alg=none".to_string(),
                "shell exec from cron payload".to_string(),
                "path traversal in /assets/<file>".to_string(),
            ],
        ),
        (
            Severity::Medium,
            "medium",
            vec![
                "open redirect on /login?next=".to_string(),
                "csrf token not bound to session".to_string(),
                "unbounded regex on /search".to_string(),
            ],
        ),
        (
            Severity::Low,
            "low",
            vec![
                "cors allows null origin".to_string(),
                "cookie set without SameSite".to_string(),
                "console.log of req.body in handler".to_string(),
            ],
        ),
    ]
}

pub(in crate::renderer) fn impact_to_severity(value: &str) -> Severity {
    match value.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

pub(in crate::renderer) fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}
