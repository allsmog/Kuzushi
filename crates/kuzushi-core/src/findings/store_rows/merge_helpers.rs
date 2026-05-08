use super::*;

pub(crate) fn fingerprint_parts(
    rule_id: &str,
    file_path: &str,
    start_line: u32,
    message: &str,
) -> String {
    let mut hasher = DefaultHasher::new();
    rule_id.hash(&mut hasher);
    file_path.hash(&mut hasher);
    start_line.hash(&mut hasher);
    message.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

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
