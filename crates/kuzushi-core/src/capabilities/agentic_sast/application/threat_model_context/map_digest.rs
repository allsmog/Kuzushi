use super::*;

pub(super) fn sections(document: &Value) -> [(&'static str, Vec<String>); 5] {
    [
        ("System overview", overview_lines(document)),
        (
            "Architecture components",
            lines(document.pointer("/dfd/nodes"), node_line),
        ),
        (
            "Data flows",
            lines(document.pointer("/dfd/flows"), flow_line),
        ),
        (
            "Trust boundaries",
            lines(document.pointer("/dfd/trustBoundaries"), boundary_line),
        ),
        (
            "Open context questions",
            lines(document.get("openQuestions"), question_line),
        ),
    ]
}

fn overview_lines(document: &Value) -> Vec<String> {
    select_threat_digest_overview(document)
        .map(|text| vec![format!("- {}", cap(text))])
        .unwrap_or_default()
}

fn lines(value: Option<&Value>, render: fn(&Value) -> Option<String>) -> Vec<String> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut lines = items
        .iter()
        .take(MAX_DIGEST_ENTRIES)
        .filter_map(render)
        .collect::<Vec<_>>();
    if items.len() > MAX_DIGEST_ENTRIES {
        lines.push(format!(
            "- {} additional elements omitted from scan context",
            items.len() - MAX_DIGEST_ENTRIES
        ));
    }
    lines
}

fn node_line(node: &Value) -> Option<String> {
    let name = field(node, &["name", "id"])?;
    let zone = field(node, &["trustZone"]).unwrap_or_else(|| "zone unspecified".into());
    let description = field(node, &["description"]).unwrap_or_default();
    Some(format!("- {name} ({zone}) · {description}"))
}

fn flow_line(flow: &Value) -> Option<String> {
    let source = field(flow, &["sourceId"])?;
    let target = field(flow, &["targetId"])?;
    let description = field(flow, &["description"]).unwrap_or_default();
    Some(format!("- {source} -> {target} · {description}"))
}

fn boundary_line(boundary: &Value) -> Option<String> {
    let name = field(boundary, &["name", "id"])?;
    let description = field(boundary, &["description"]).unwrap_or_default();
    Some(format!("- {name} · {description}"))
}

fn question_line(question: &Value) -> Option<String> {
    Some(format!("- {}", cap(question.as_str()?)))
}
