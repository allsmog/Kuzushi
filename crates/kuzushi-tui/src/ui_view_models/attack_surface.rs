use crate::app::JsonFileState;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttackSurfaceRiskModel {
    pub(crate) summary: String,
    pub(crate) hot_surfaces: Vec<AttackSurfaceRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttackSurfaceRow {
    pub(crate) title: String,
    pub(crate) framework: String,
    pub(crate) tier: String,
    pub(crate) score: u64,
}

pub(crate) fn attack_surface_risk_model(artifact: JsonFileState) -> Option<AttackSurfaceRiskModel> {
    let value = match artifact {
        JsonFileState::Present(value) if value.is_object() => value,
        JsonFileState::Missing => return None,
        JsonFileState::NonFile => return Some(non_file_attack_surface_model()),
        JsonFileState::Present(_) | JsonFileState::Malformed | JsonFileState::Unreadable => {
            return Some(malformed_attack_surface_model())
        }
    };
    if attack_surface_status(&value).as_deref() == Some("skipped") {
        return None;
    }
    let risk_tiers = summary_risk_tiers(&value);
    let frameworks = framework_counts(&value);
    let top_surface = top_surface_label(&value);
    Some(AttackSurfaceRiskModel {
        summary: attack_surface_risk_summary(
            summary_usize(&value, "highRisk"),
            summary_u64(&value, "maxRiskScore"),
            &risk_tiers,
            &frameworks,
            top_surface.as_deref(),
        ),
        hot_surfaces: hot_surface_rows(&value),
    })
}

fn malformed_attack_surface_model() -> AttackSurfaceRiskModel {
    AttackSurfaceRiskModel {
        summary: format!("malformed {}", attack_surface_artifact_leaf()),
        hot_surfaces: Vec::new(),
    }
}

fn non_file_attack_surface_model() -> AttackSurfaceRiskModel {
    AttackSurfaceRiskModel {
        summary: format!("{} is not a file", attack_surface_artifact_leaf()),
        hot_surfaces: Vec::new(),
    }
}

fn attack_surface_artifact_leaf() -> &'static str {
    "attack-surface.json"
}

fn attack_surface_status(value: &serde_json::Value) -> Option<String> {
    value
        .get("status")
        .or_else(|| value.pointer("/summary/status"))
        .and_then(serde_json::Value::as_str)
        .map(|status| status.to_ascii_lowercase())
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

fn framework_counts(value: &serde_json::Value) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    let Some(surfaces) = value.get("surfaces").and_then(serde_json::Value::as_array) else {
        return counts;
    };
    for surface in surfaces {
        if let Some(framework) = surface_framework(surface) {
            *counts.entry(framework.to_string()).or_default() += 1;
        }
    }
    counts
}

fn surface_framework(surface: &serde_json::Value) -> Option<&str> {
    surface
        .get("framework")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|framework| !framework.is_empty())
}

fn surface_label(tier: Option<&str>, title: Option<&str>) -> Option<String> {
    match (tier, title) {
        (Some(tier), Some(title)) => Some(format!("{tier} {title}")),
        (Some(tier), None) => Some(tier.to_string()),
        (None, Some(title)) => Some(title.to_string()),
        (None, None) => None,
    }
}

fn hot_surface_rows(value: &serde_json::Value) -> Vec<AttackSurfaceRow> {
    value
        .get("surfaces")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(surface_row)
        .take(8)
        .collect()
}

fn surface_row(value: &serde_json::Value) -> Option<AttackSurfaceRow> {
    let title = value.get("title")?.as_str()?.trim();
    if title.is_empty() {
        return None;
    }
    Some(AttackSurfaceRow {
        title: title.to_string(),
        framework: value
            .get("framework")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        tier: value
            .pointer("/risk/tier")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        score: value
            .pointer("/risk/score")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default(),
    })
}

fn attack_surface_risk_summary(
    high_risk: usize,
    max_risk_score: u64,
    risk_tiers: &BTreeMap<String, usize>,
    frameworks: &BTreeMap<String, usize>,
    top_surface: Option<&str>,
) -> String {
    let top = top_surface.unwrap_or("none");
    let mut parts = vec![
        format!("{high_risk} high/critical"),
        format!("max {max_risk_score}"),
    ];
    if let Some(tiers) = risk_tier_summary(risk_tiers) {
        parts.push(format!("tiers {tiers}"));
    }
    if let Some(frameworks) = framework_summary(frameworks) {
        parts.push(format!("frameworks {frameworks}"));
    }
    parts.push(format!("top {top}"));
    parts.join(", ")
}

fn framework_summary(frameworks: &BTreeMap<String, usize>) -> Option<String> {
    count_summary(frameworks)
}

fn risk_tier_summary(tiers: &BTreeMap<String, usize>) -> Option<String> {
    let mut keys = tiers.keys().collect::<Vec<_>>();
    keys.sort_by(|left, right| {
        tier_rank(left)
            .cmp(&tier_rank(right))
            .then_with(|| left.cmp(right))
    });
    count_summary_for_keys(keys, tiers)
}

fn count_summary(counts: &BTreeMap<String, usize>) -> Option<String> {
    count_summary_for_keys(counts.keys().collect(), counts)
}

fn count_summary_for_keys(keys: Vec<&String>, counts: &BTreeMap<String, usize>) -> Option<String> {
    let summary = keys
        .into_iter()
        .filter_map(|key| count_segment(key, counts.get(key).copied()))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then_some(summary)
}

fn count_segment(label: &str, count: Option<usize>) -> Option<String> {
    let count = count.filter(|count| *count > 0)?;
    Some(format!("{label}={count}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_surface_model_reads_risk_tier_distribution() {
        let model = attack_surface_risk_model(JsonFileState::Present(serde_json::json!({
            "summary": {
                "highRisk": 2,
                "maxRiskScore": 100,
                "byRiskTier": {"critical": 1, "high": 1, "medium": 2}
            },
            "surfaces": [{
                "framework": "Spring",
                "title": "POST /admin",
                "risk": {"tier": "critical"}
            }, {
                "framework": "Rails",
                "title": "POST /admin/jobs",
                "risk": {"tier": "high"}
            }, {
                "framework": "Next.js",
                "title": "POST /api/session",
                "risk": {"tier": "medium"}
            }, {
                "framework": "Spring",
                "title": "POST /admin/users",
                "risk": {"tier": "medium"}
            }]
        })))
        .unwrap();

        assert_eq!(
            model.summary,
            "2 high/critical, max 100, tiers critical=1, high=1, medium=2, frameworks Next.js=1, Rails=1, Spring=2, top critical POST /admin"
        );
    }

    #[test]
    fn attack_surface_model_surfaces_malformed_artifact() {
        let model = attack_surface_risk_model(JsonFileState::Malformed).unwrap();

        assert_eq!(
            model.summary,
            format!("malformed {}", attack_surface_artifact_leaf())
        );
    }

    #[test]
    fn attack_surface_model_surfaces_non_object_artifact() {
        let model =
            attack_surface_risk_model(JsonFileState::Present(serde_json::json!([]))).unwrap();

        assert_eq!(
            model.summary,
            format!("malformed {}", attack_surface_artifact_leaf())
        );
    }

    #[test]
    fn attack_surface_model_surfaces_non_file_artifact() {
        let model = attack_surface_risk_model(JsonFileState::NonFile).unwrap();

        assert_eq!(
            model.summary,
            format!("{} is not a file", attack_surface_artifact_leaf())
        );
    }

    #[test]
    fn attack_surface_model_keeps_missing_artifact_empty() {
        assert!(attack_surface_risk_model(JsonFileState::Missing).is_none());
    }

    #[test]
    fn attack_surface_model_keeps_skipped_placeholder_empty() {
        assert!(attack_surface_risk_model(JsonFileState::Present(
            serde_json::json!({"status": "skipped"}),
        ))
        .is_none());
    }
}
