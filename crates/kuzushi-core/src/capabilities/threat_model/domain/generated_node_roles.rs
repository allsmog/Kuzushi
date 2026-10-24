//! Fresh model output must name a DFD role before compatibility normalization.
use super::*;

pub(crate) fn require_generated_node_roles(document: &Value) -> Result<()> {
    let Some(dfd) = document.get("dfd") else {
        return Ok(());
    };
    let (field, collection) = selected_node_collection(dfd);
    let Some(nodes) = collection.and_then(Value::as_array) else {
        return Ok(());
    };
    nodes.iter().enumerate().try_for_each(|(index, node)| {
        require_node_role(node, &format!("/dfd/{field}/{index}/type"))
    })
}

fn selected_node_collection(dfd: &Value) -> (&str, Option<&Value>) {
    match dfd.get("nodes") {
        Some(nodes) => ("nodes", Some(nodes)),
        None => ("elements", dfd.get("elements")),
    }
}

fn require_node_role(node: &Value, pointer: &str) -> Result<()> {
    let role = node.get("type").and_then(Value::as_str).with_context(|| {
        format!("Generated DFD node at {pointer} requires a text role: process, external-entity or data-store")
    })?;
    anyhow::ensure!(
        matches!(recognized_dfd_type(role), Some("process" | "external-entity" | "data-store")),
        "Unsupported generated DFD node role at {pointer}: {}. Expected process, external-entity or data-store. Put flows in dfd.flows.",
        quoted_role(role)
    );
    Ok(())
}

fn quoted_role(role: &str) -> String {
    let preview = role.chars().take(80).collect::<String>();
    let suffix = if preview.len() < role.len() {
        "…"
    } else {
        ""
    };
    json!(format!("{preview}{suffix}")).to_string()
}

#[cfg(test)]
mod tests;
