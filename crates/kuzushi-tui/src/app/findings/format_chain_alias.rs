use super::*;

pub fn format_chain_alias(index: usize) -> String {
    format!("C-{:02}", index + 1)
}

pub fn parse_chain_alias(reference: &str) -> Option<usize> {
    let reference = reference.trim();
    let suffix = reference
        .strip_prefix("C-")
        .or_else(|| reference.strip_prefix("c-"))?;
    let index = suffix.parse::<usize>().ok()?;
    index.checked_sub(1)
}

pub(crate) fn sorted_chain_aliases(chains: &[ExploitChain]) -> Vec<(String, ExploitChain)> {
    let mut indexed: Vec<&ExploitChain> = chains.iter().collect();
    indexed.sort_by(|a, b| {
        let by_severity = a.severity.rank().cmp(&b.severity.rank());
        if by_severity == std::cmp::Ordering::Equal {
            a.id.cmp(&b.id)
        } else {
            by_severity
        }
    });
    indexed
        .into_iter()
        .enumerate()
        .map(|(index, chain)| (format_chain_alias(index), chain.clone()))
        .collect()
}

pub fn format_alias_table(
    findings: &[Finding],
    chains: &[ExploitChain],
    filter: Option<&str>,
) -> String {
    let chain_aliases = sorted_chain_aliases(chains);
    let finding_aliases = sorted_finding_aliases(findings);
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for (alias, chain) in &chain_aliases {
        if let Some(prefix) = filter {
            if !alias.to_ascii_uppercase().starts_with(prefix) {
                continue;
            }
        }
        rows.push((alias.clone(), chain.id.clone(), chain.title.clone()));
    }
    for (alias, finding) in &finding_aliases {
        if let Some(prefix) = filter {
            if !alias.to_ascii_uppercase().starts_with(prefix) {
                continue;
            }
        }
        let target = finding.fingerprint.chars().take(12).collect::<String>();
        rows.push((alias.clone(), target, finding.title.clone()));
    }
    if rows.is_empty() {
        return match filter {
            Some(prefix) => format!("No aliases match \"{prefix}\""),
            None => "No aliases for the current run".to_string(),
        };
    }
    let alias_w = rows
        .iter()
        .map(|(a, _, _)| a.len())
        .max()
        .unwrap_or(0)
        .max(5);
    let target_w = rows
        .iter()
        .map(|(_, t, _)| t.len())
        .max()
        .unwrap_or(0)
        .max(6);
    let mut lines = Vec::new();
    lines.push(format!(
        "{:<alias_w$}  {:<target_w$}  title",
        "alias", "target",
    ));
    lines.push(format!("{:─<alias_w$}  {:─<target_w$}  ─────", "", "",));
    for (alias, target, title) in rows {
        lines.push(format!("{alias:<alias_w$}  {target:<target_w$}  {title}",));
    }
    lines.join("\n")
}

pub(crate) fn short_fingerprint(fingerprint: &str) -> String {
    fingerprint.chars().take(8).collect()
}
