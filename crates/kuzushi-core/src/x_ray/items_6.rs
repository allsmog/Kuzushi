use super::prelude::*;
use super::*;

pub(crate) fn parse_entry_point_summary_counts(markdown: &str) -> Option<XRayEntryPointCounts> {
    for line in markdown.lines() {
        let line = line.trim().trim_start_matches('>').trim();
        let lower = line.to_ascii_lowercase();
        if !lower.contains("entry point")
            && !lower.contains("permissionless")
            && !lower.contains("role-gated")
            && !lower.contains("role gated")
            && !lower.contains("admin-only")
            && !lower.contains("admin only")
        {
            continue;
        }

        let total = count_before_phrase(&lower, "entry point");
        let permissionless = count_before_phrase(&lower, "permissionless");
        let role_gated = count_before_phrase(&lower, "role-gated")
            .or_else(|| count_before_phrase(&lower, "role gated"));
        let admin_only = count_before_phrase(&lower, "admin-only")
            .or_else(|| count_before_phrase(&lower, "admin only"));

        if total.is_none()
            && permissionless.is_none()
            && role_gated.is_none()
            && admin_only.is_none()
        {
            continue;
        }

        let permissionless = permissionless.unwrap_or(0);
        let role_gated = role_gated.unwrap_or(0);
        let admin_only = admin_only.unwrap_or(0);
        return Some(XRayEntryPointCounts {
            permissionless,
            role_gated,
            admin_only,
            total: total.unwrap_or(permissionless + role_gated + admin_only),
        });
    }
    None
}

pub(crate) fn count_before_phrase(line: &str, phrase: &str) -> Option<usize> {
    let index = line.find(phrase)?;
    let prefix = line[..index].trim_end();
    let digits = prefix
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<Vec<_>>();
    if digits.is_empty() {
        return None;
    }
    let value = digits.into_iter().rev().collect::<String>();
    value.parse().ok()
}

pub(crate) fn count_entries_in_section(markdown: &str, heading: &str) -> usize {
    extract_heading_section(markdown, heading)
        .map(|section| count_entry_rows(&section))
        .unwrap_or(0)
}

pub(crate) fn count_entry_rows(markdown: &str) -> usize {
    let heading_rows = markdown
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let hashes = trimmed.chars().take_while(|ch| *ch == '#').count();
            (3..=5).contains(&hashes).then(|| trimmed[hashes..].trim())
        })
        .filter(|label| {
            let lower = label.to_ascii_lowercase();
            !lower.contains("permissionless")
                && !lower.contains("role-gated")
                && !lower.contains("role gated")
                && !lower.contains("admin-only")
                && !lower.contains("admin only")
                && is_likely_entry_label(label)
        })
        .count();

    let table_rows = markdown
        .lines()
        .filter(|line| line.trim_start().starts_with('|'))
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !lower.contains("entry")
                && !lower.contains("permission")
                && !lower.contains("role")
                && !lower.contains("admin")
                && !lower.contains("---")
                && is_likely_entry_label(line.split('|').nth(1).unwrap_or_default())
        })
        .count();

    heading_rows.max(table_rows)
}
