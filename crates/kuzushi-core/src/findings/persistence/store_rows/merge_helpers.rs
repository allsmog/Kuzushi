use super::*;

pub(crate) fn merge_tool_list(existing: &str, incoming: &str) -> String {
    let mut tools: std::collections::BTreeSet<String> = existing
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    tools.insert(incoming.trim().to_string());
    tools.into_iter().collect::<Vec<_>>().join(",")
}

pub(crate) fn merge_vuln_source(
    existing: Option<VulnSource>,
    incoming: Option<VulnSource>,
) -> Option<VulnSource> {
    existing.or(incoming)
}
