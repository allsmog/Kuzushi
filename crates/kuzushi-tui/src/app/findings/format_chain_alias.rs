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
    let rows = alias_table_rows(findings, chains, filter);
    if rows.is_empty() {
        return empty_alias_message(filter);
    }
    render_alias_table(&rows)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AliasTableRow {
    alias: String,
    target: String,
    title: String,
}

fn alias_table_rows(
    findings: &[Finding],
    chains: &[ExploitChain],
    filter: Option<&str>,
) -> Vec<AliasTableRow> {
    let mut rows = chain_alias_rows(chains, filter);
    rows.extend(finding_alias_rows(findings, filter));
    rows
}

fn chain_alias_rows(chains: &[ExploitChain], filter: Option<&str>) -> Vec<AliasTableRow> {
    sorted_chain_aliases(chains)
        .into_iter()
        .filter(|(alias, _)| alias_matches_filter(alias, filter))
        .map(|(alias, chain)| AliasTableRow {
            alias,
            target: chain.id,
            title: chain.title,
        })
        .collect()
}

fn finding_alias_rows(findings: &[Finding], filter: Option<&str>) -> Vec<AliasTableRow> {
    kuzushi_core::sorted_finding_alias_indices(findings)
        .into_iter()
        .filter(|(alias, _)| alias_matches_filter(alias, filter))
        .filter_map(|(alias, index)| finding_alias_row(alias, findings.get(index)))
        .collect()
}

fn finding_alias_row(alias: String, finding: Option<&Finding>) -> Option<AliasTableRow> {
    finding.map(|finding| AliasTableRow {
        alias,
        target: finding.fingerprint.chars().take(12).collect(),
        title: finding.title.clone(),
    })
}

fn alias_matches_filter(alias: &str, filter: Option<&str>) -> bool {
    match filter {
        Some(prefix) => alias.to_ascii_uppercase().starts_with(prefix),
        None => true,
    }
}

fn empty_alias_message(filter: Option<&str>) -> String {
    match filter {
        Some(prefix) => format!("No aliases match \"{prefix}\""),
        None => "No aliases for the current run".to_string(),
    }
}

fn render_alias_table(rows: &[AliasTableRow]) -> String {
    let (alias_w, target_w) = alias_table_widths(rows);
    let mut lines = Vec::new();
    lines.push(format!(
        "{:<alias_w$}  {:<target_w$}  title",
        "alias", "target",
    ));
    lines.push(format!("{:─<alias_w$}  {:─<target_w$}  ─────", "", "",));
    lines.extend(rows.iter().map(|row| {
        let alias = &row.alias;
        let target = &row.target;
        let title = &row.title;
        format!("{alias:<alias_w$}  {target:<target_w$}  {title}",)
    }));
    lines.join("\n")
}

fn alias_table_widths(rows: &[AliasTableRow]) -> (usize, usize) {
    let alias_w = rows
        .iter()
        .map(|row| row.alias.len())
        .max()
        .unwrap_or(0)
        .max(5);
    let target_w = rows
        .iter()
        .map(|row| row.target.len())
        .max()
        .unwrap_or(0)
        .max(6);
    (alias_w, target_w)
}

pub(crate) fn short_fingerprint(fingerprint: &str) -> String {
    fingerprint.chars().take(8).collect()
}
