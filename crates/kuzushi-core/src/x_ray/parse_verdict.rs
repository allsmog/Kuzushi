use super::*;

pub(crate) fn parse_verdict(markdown: &str) -> XRayVerdict {
    let section =
        extract_heading_section(markdown, "x-ray verdict").unwrap_or_else(|| markdown.to_string());
    let tier = find_verdict_tier(&section);
    let cleaned = clean_verdict_tiers(&section);
    let summary = first_meaningful_line(&cleaned)
        .or_else(|| first_meaningful_line(markdown))
        .unwrap_or_default();
    XRayVerdict { tier, summary }
}

pub(crate) fn find_verdict_tier(text: &str) -> Option<String> {
    const TIERS: [&str; 7] = [
        "FORTIFIED",
        "HARDENED",
        "ADEQUATE",
        "READY",
        "WATCH",
        "FRAGILE",
        "EXPOSED",
    ];
    let normalized = text
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::to_ascii_uppercase)
        .collect::<Vec<_>>();
    TIERS
        .iter()
        .find(|tier| normalized.iter().any(|token| token == **tier))
        .map(|tier| (*tier).to_string())
}

pub(crate) fn clean_verdict_tiers(text: &str) -> String {
    text.lines()
        .map(|line| {
            line.split_whitespace()
                .filter(|token| find_verdict_tier(token).is_none())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn first_meaningful_line(markdown: &str) -> Option<String> {
    markdown.lines().find_map(|line| {
        let cleaned = line
            .trim_start_matches('#')
            .trim_start_matches('>')
            .replace("**", "")
            .trim_start_matches(['-', '*', ' ', ':'])
            .trim()
            .to_string();
        (!cleaned.is_empty() && !cleaned.chars().all(|ch| "-|:".contains(ch))).then_some(cleaned)
    })
}

pub(crate) fn parse_entry_point_counts(markdown: &str) -> XRayEntryPointCounts {
    if let Some(counts) = parse_entry_point_summary_counts(markdown) {
        return counts;
    }

    let permissionless = count_entries_in_section(markdown, "permissionless");
    let role_gated = count_entries_in_section(markdown, "role-gated")
        + count_entries_in_section(markdown, "role gated");
    let admin_only = count_entries_in_section(markdown, "admin-only")
        + count_entries_in_section(markdown, "admin only");
    let sectional_total = permissionless + role_gated + admin_only;
    let fallback_total = count_entry_rows(markdown);
    XRayEntryPointCounts {
        permissionless,
        role_gated,
        admin_only,
        total: if sectional_total > 0 {
            sectional_total
        } else {
            fallback_total
        },
    }
}
