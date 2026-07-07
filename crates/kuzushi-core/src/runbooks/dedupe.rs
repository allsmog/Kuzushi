use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DedupeMethod {
    Deterministic,
    Semantic,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DedupeCluster {
    pub cluster_id: String,
    pub representative: String,
    pub members: Vec<String>,
    pub method: DedupeMethod,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
}

impl DedupeCluster {
    pub fn singleton(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            cluster_id: format!("cluster-{id}"),
            representative: id.clone(),
            members: vec![id],
            method: DedupeMethod::Deterministic,
            rationale: "singleton".to_string(),
            confidence: Some("high".to_string()),
        }
    }

    pub fn propagates_to(&self, finding_id: &str) -> bool {
        self.members.iter().any(|member| member == finding_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DedupeClusterArtifact {
    pub schema_version: String,
    pub runbook_id: String,
    pub clusters: Vec<DedupeCluster>,
}

impl DedupeClusterArtifact {
    pub fn new(runbook_id: impl Into<String>, clusters: Vec<DedupeCluster>) -> Self {
        Self {
            schema_version: "confirm.dedupe-clusters.v1".to_string(),
            runbook_id: runbook_id.into(),
            clusters,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_cluster_keeps_member_visible() {
        let cluster = DedupeCluster::singleton("F-001");
        assert_eq!(cluster.representative, "F-001");
        assert!(cluster.propagates_to("F-001"));
    }
}
