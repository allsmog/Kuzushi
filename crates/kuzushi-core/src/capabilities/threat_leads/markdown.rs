use serde_json::Value;

pub(super) fn render_threat_leads_markdown(report: &Value) -> String {
    let mut lines = vec![
        "# Threat Leads".to_string(),
        String::new(),
        format!(
            "Generated {} lead cards from threat model, X-Ray, and bounded source evidence.",
            report["leadCount"].as_u64().unwrap_or_default()
        ),
    ];
    append_priority_leads(&mut lines, report);
    append_lead_details(&mut lines, report);
    lines.push(String::new());
    lines.join("\n")
}

fn append_priority_leads(lines: &mut Vec<String>, report: &Value) {
    let priority_leads = report
        .get("leads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(4)
        .collect::<Vec<_>>();
    if priority_leads.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("Priority lead cards:".to_string());
    for lead in priority_leads {
        lines.push(priority_lead_line(lead));
    }
}

fn priority_lead_line(lead: &Value) -> String {
    let threat_id = lead["threatId"].as_str().unwrap_or("unknown");
    let title = lead["title"].as_str().unwrap_or("untitled");
    let pattern = lead["pattern"].as_str().unwrap_or("unknown");
    let candidates = lead["candidateFiles"]
        .as_array()
        .into_iter()
        .flatten()
        .take(3)
        .filter_map(|candidate| candidate["path"].as_str())
        .collect::<Vec<_>>()
        .join(", ");
    format!("- {threat_id}: {title} [{pattern}] candidates: {candidates}")
}

fn append_lead_details(lines: &mut Vec<String>, report: &Value) {
    for lead in report
        .get("leads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        append_lead_detail(lines, lead);
    }
}

fn append_lead_detail(lines: &mut Vec<String>, lead: &Value) {
    let threat_id = lead["threatId"].as_str().unwrap_or("unknown");
    let title = lead["title"].as_str().unwrap_or("untitled");
    lines.push(String::new());
    lines.push(format!("## {threat_id}: {title}"));
    push_optional_line(lines, "Pattern", lead["pattern"].as_str());
    push_optional_line(lines, "Source", lead["source"].as_str());
    push_optional_line(lines, "Sink", lead["sink"].as_str());
    push_optional_line(lines, "Classification", lead["classification"].as_str());
    push_optional_line(lines, "Confidence", lead["confidence"].as_str());
    append_candidate_lines(lines, lead);
}

fn append_candidate_lines(lines: &mut Vec<String>, lead: &Value) {
    let Some(candidates) = lead["candidateFiles"].as_array() else {
        return;
    };
    lines.push("Top candidate files:".to_string());
    for candidate in candidates.iter().take(5) {
        lines.push(candidate_line(candidate));
    }
}

fn candidate_line(candidate: &Value) -> String {
    let path = candidate["path"].as_str().unwrap_or("unknown");
    let classification = candidate["classification"].as_str().unwrap_or("unknown");
    let evidence = candidate["evidence"]
        .as_array()
        .into_iter()
        .flatten()
        .take(8)
        .filter_map(|item| item["term"].as_str())
        .collect::<Vec<_>>()
        .join(", ");
    format!("  - `{path}` ({classification}) evidence: {evidence}")
}

fn push_optional_line(lines: &mut Vec<String>, label: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        lines.push(format!("{label}: {value}"));
    }
}
