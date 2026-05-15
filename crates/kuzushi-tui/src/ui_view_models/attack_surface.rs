use std::path::Path;
use std::{collections::BTreeMap, fs};

#[derive(Debug, Clone, PartialEq)]
pub struct AttackSurfaceRiskModel {
    pub high_risk: usize,
    pub max_risk_score: u64,
    pub risk_tiers: BTreeMap<String, usize>,
    pub top_surface: Option<String>,
}

pub fn attack_surface_risk_model(run_dir: &Path) -> Option<AttackSurfaceRiskModel> {
    let value = read_attack_surface(run_dir)?;
    Some(AttackSurfaceRiskModel {
        high_risk: summary_usize(&value, "highRisk"),
        max_risk_score: summary_u64(&value, "maxRiskScore"),
        risk_tiers: summary_risk_tiers(&value),
        top_surface: top_surface_label(&value),
    })
}

fn read_attack_surface(run_dir: &Path) -> Option<serde_json::Value> {
    let path = run_dir.join("attack-surface.json");
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn summary_usize(value: &serde_json::Value, key: &str) -> usize {
    summary_u64(value, key) as usize
}

fn summary_u64(value: &serde_json::Value, key: &str) -> u64 {
    value
        .get("summary")
        .and_then(|summary| summary.get(key))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default()
}

fn summary_risk_tiers(value: &serde_json::Value) -> BTreeMap<String, usize> {
    value
        .pointer("/summary/byRiskTier")
        .and_then(serde_json::Value::as_object)
        .map(risk_tiers_from_object)
        .unwrap_or_default()
}

fn risk_tiers_from_object(
    object: &serde_json::Map<String, serde_json::Value>,
) -> BTreeMap<String, usize> {
    object
        .iter()
        .filter_map(|(tier, count)| {
            count
                .as_u64()
                .map(|count| (tier.to_string(), count as usize))
        })
        .collect()
}

fn top_surface_label(value: &serde_json::Value) -> Option<String> {
    let surface = value.get("surfaces")?.as_array()?.first()?;
    let tier = surface
        .pointer("/risk/tier")
        .and_then(serde_json::Value::as_str);
    let title = surface.get("title").and_then(serde_json::Value::as_str);
    surface_label(tier, title)
}

fn surface_label(tier: Option<&str>, title: Option<&str>) -> Option<String> {
    match (tier, title) {
        (Some(tier), Some(title)) => Some(format!("{tier} {title}")),
        (Some(tier), None) => Some(tier.to_string()),
        (None, Some(title)) => Some(title.to_string()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_surface_model_reads_risk_tier_distribution() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("attack-surface.json"),
            serde_json::json!({
                "summary": {
                    "highRisk": 2,
                    "maxRiskScore": 100,
                    "byRiskTier": {"critical": 1, "high": 1, "medium": 2}
                },
                "surfaces": [{
                    "title": "POST /admin",
                    "risk": {"tier": "critical"}
                }]
            })
            .to_string(),
        )
        .unwrap();

        let model = attack_surface_risk_model(temp.path()).unwrap();

        assert_eq!(model.risk_tiers.get("critical"), Some(&1));
        assert_eq!(model.risk_tiers.get("high"), Some(&1));
        assert_eq!(model.risk_tiers.get("medium"), Some(&2));
        assert_eq!(model.top_surface.as_deref(), Some("critical POST /admin"));
    }
}
