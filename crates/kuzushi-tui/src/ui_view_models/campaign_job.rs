use kuzushi_core::capabilities::campaign::snapshot::CampaignJobSnapshot;
use serde_json::Value;

pub(crate) fn campaign_job_scope_label(job: &CampaignJobSnapshot) -> String {
    let scope = discovery_scope_label(&job.input, job.shard.as_deref());
    match job.threat_title.as_deref().or(job.threat_id.as_deref()) {
        Some(threat) => format!("{scope} / {threat}"),
        None => scope.to_string(),
    }
}

fn discovery_scope_label<'a>(input: &'a Value, legacy_shard: Option<&'a str>) -> &'a str {
    input
        .pointer("/scanScopeRef/scopeId")
        .and_then(Value::as_str)
        .or(legacy_shard)
        .unwrap_or("workspace")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepted_scope_precedes_legacy_shard() {
        let input = json!({"scanScopeRef": {"scopeId": "accepted-files"}});
        assert_eq!(
            discovery_scope_label(&input, Some("legacy")),
            "accepted-files"
        );
    }

    #[test]
    fn absent_scope_preserves_legacy_and_workspace_labels() {
        assert_eq!(
            discovery_scope_label(&Value::Null, Some("legacy")),
            "legacy"
        );
        assert_eq!(discovery_scope_label(&Value::Null, None), "workspace");
    }

    #[test]
    fn malformed_scope_does_not_manufacture_an_identity() {
        let input = json!({"scanScopeRef": {"scopeId": 7}});
        assert_eq!(discovery_scope_label(&input, None), "workspace");
    }
}
