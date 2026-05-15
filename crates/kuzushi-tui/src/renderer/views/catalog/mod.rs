use super::*;
pub(in crate::renderer) use super::*;
use crate::ui_view_models::AttackSurfaceRiskModel;

pub(in crate::renderer) use catalog_lines::*;
pub(in crate::renderer) use home_lines::*;
pub(in crate::renderer) use recommend_lines::*;
mod catalog_lines;
mod home_lines;
mod recommend_lines;
pub(crate) use catalog_lines::catalog_lines;
pub(crate) use home_lines::home_lines;
pub(crate) use recommend_lines::recommend_lines;
use std::collections::BTreeMap;

fn attack_surface_risk_line(surface: &AttackSurfaceRiskModel, width: u16) -> Line<'static> {
    detail(
        "surface risk",
        &fit(
            &attack_surface_risk_summary(surface),
            detail_value_width(width),
        ),
    )
}

fn attack_surface_risk_summary(surface: &AttackSurfaceRiskModel) -> String {
    let top = surface.top_surface.as_deref().unwrap_or("none");
    let mut parts = vec![
        format!("{} high/critical", surface.high_risk),
        format!("max {}", surface.max_risk_score),
    ];
    if let Some(tiers) = risk_tier_summary(&surface.risk_tiers) {
        parts.push(format!("tiers {tiers}"));
    }
    parts.push(format!("top {top}"));
    parts.join(", ")
}

fn detail_value_width(width: u16) -> usize {
    (width as usize).saturating_sub(20).max(12)
}

fn risk_tier_summary(tiers: &BTreeMap<String, usize>) -> Option<String> {
    let mut keys = tiers.keys().collect::<Vec<_>>();
    keys.sort_by(|left, right| {
        tier_rank(left)
            .cmp(&tier_rank(right))
            .then_with(|| left.cmp(right))
    });
    let summary = keys
        .into_iter()
        .filter_map(|tier| tier_count_segment(tier, tiers.get(tier).copied()))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then_some(summary)
}

fn tier_count_segment(tier: &str, count: Option<usize>) -> Option<String> {
    let count = count.filter(|count| *count > 0)?;
    Some(format!("{tier}={count}"))
}

fn tier_rank(tier: &str) -> usize {
    match tier {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}
