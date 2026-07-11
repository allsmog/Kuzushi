use crate::ui_view_models::{DfdModel, RiskByModule};
use kuzushi_core::findings::ReviewDecisionRecord;
use kuzushi_core::Finding;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Default)]
pub(super) struct ViewModelFragmentCache {
    visible_findings: Option<CachedVisibleFindings>,
    risk_by_module: Option<CachedRiskByModule>,
    dfd_model: Option<CachedDfdModel>,
}

impl ViewModelFragmentCache {
    pub(super) fn visible_findings(
        &self,
        key: &VisibleFindingsCacheKey,
    ) -> Option<Vec<VisibleFindingProjection>> {
        self.visible_findings
            .as_ref()
            .filter(|cache| &cache.key == key)
            .map(|cache| cache.projected.clone())
    }

    pub(super) fn cache_visible_findings(
        &mut self,
        key: VisibleFindingsCacheKey,
        projected: Vec<VisibleFindingProjection>,
    ) {
        self.visible_findings = Some(CachedVisibleFindings { key, projected });
    }

    pub(super) fn risk_by_module(&self, key: &RiskByModuleCacheKey) -> Option<RiskByModule> {
        self.risk_by_module
            .as_ref()
            .filter(|cache| &cache.key == key)
            .map(|cache| cache.risk.clone())
    }

    pub(super) fn cache_risk_by_module(&mut self, key: RiskByModuleCacheKey, risk: RiskByModule) {
        self.risk_by_module = Some(CachedRiskByModule { key, risk });
    }

    pub(super) fn dfd_model(&self, key: &DfdModelCacheKey) -> Option<DfdModel> {
        self.dfd_model
            .as_ref()
            .filter(|cache| &cache.key == key)
            .map(|cache| cache.model.clone())
    }

    pub(super) fn cache_dfd_model(&mut self, key: DfdModelCacheKey, model: DfdModel) {
        self.dfd_model = Some(CachedDfdModel { key, model });
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct VisibleFindingProjection {
    pub(crate) alias: String,
    pub(crate) finding: Finding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VisibleFindingsCacheKey {
    findings: ViewModelVersion,
    review_decisions: ViewModelVersion,
    target_base: Option<String>,
    active_component: Option<String>,
    active_filter: Option<String>,
}

impl VisibleFindingsCacheKey {
    pub(crate) fn from_app_parts(
        findings: &[Finding],
        review_decisions: &[ReviewDecisionRecord],
        target_base: Option<String>,
        active_component: Option<String>,
        active_filter: Option<String>,
    ) -> Self {
        Self {
            findings: ViewModelVersion::from_findings(findings),
            review_decisions: ViewModelVersion::from_review_decisions(review_decisions),
            target_base,
            active_component,
            active_filter,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RiskByModuleCacheKey {
    findings: ViewModelVersion,
}

impl RiskByModuleCacheKey {
    pub(crate) fn from_findings(findings: &[Finding]) -> Self {
        Self {
            findings: ViewModelVersion::from_risk_findings(findings),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DfdModelCacheKey {
    threat_doc: ViewModelVersion,
}

impl DfdModelCacheKey {
    pub(crate) fn from_threat_doc(doc: Option<&serde_json::Value>) -> Self {
        Self {
            threat_doc: ViewModelVersion::from_threat_doc(doc),
        }
    }
}

#[derive(Debug)]
struct CachedVisibleFindings {
    key: VisibleFindingsCacheKey,
    projected: Vec<VisibleFindingProjection>,
}

#[derive(Debug)]
struct CachedRiskByModule {
    key: RiskByModuleCacheKey,
    risk: RiskByModule,
}

#[derive(Debug)]
struct CachedDfdModel {
    key: DfdModelCacheKey,
    model: DfdModel,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ViewModelVersion(u64);

impl ViewModelVersion {
    fn from_findings(findings: &[Finding]) -> Self {
        version_from(|hasher| hash_findings(findings, hasher))
    }

    fn from_risk_findings(findings: &[Finding]) -> Self {
        version_from(|hasher| hash_risk_findings(findings, hasher))
    }

    fn from_review_decisions(decisions: &[ReviewDecisionRecord]) -> Self {
        version_from(|hasher| hash_review_decisions(decisions, hasher))
    }

    fn from_threat_doc(doc: Option<&serde_json::Value>) -> Self {
        version_from(|hasher| hash_threat_doc(doc, hasher))
    }
}

fn version_from(hash: impl FnOnce(&mut DefaultHasher)) -> ViewModelVersion {
    let mut hasher = DefaultHasher::new();
    hash(&mut hasher);
    ViewModelVersion(hasher.finish())
}

fn hash_findings(findings: &[Finding], hasher: &mut DefaultHasher) {
    findings.len().hash(hasher);
    for finding in findings {
        hash_finding_projection_fields(finding, hasher);
    }
}

fn hash_risk_findings(findings: &[Finding], hasher: &mut DefaultHasher) {
    findings.len().hash(hasher);
    for finding in findings {
        finding.file_path.hash(hasher);
        finding.severity.as_str().hash(hasher);
    }
}

fn hash_finding_projection_fields(finding: &Finding, hasher: &mut DefaultHasher) {
    finding.id.hash(hasher);
    finding.identity_id.hash(hasher);
    finding.created_at.hash(hasher);
    finding.fingerprint.hash(hasher);
    finding.dedup_key.hash(hasher);
    finding.file_path.hash(hasher);
    finding.scan_id.hash(hasher);
    finding.severity.as_str().hash(hasher);
    finding.corroboration_count.hash(hasher);
    hash_debug(&finding.static_proof_state, hasher);
    hash_debug(&finding.triage, hasher);
    hash_debug(&finding.verification, hasher);
    hash_debug(&finding.vuln_source, hasher);
    hash_debug(&finding.sources, hasher);
}

fn hash_review_decisions(decisions: &[ReviewDecisionRecord], hasher: &mut DefaultHasher) {
    decisions.len().hash(hasher);
    for record in decisions {
        record.id.hash(hasher);
        record.finding_id.hash(hasher);
        record.identity_id.hash(hasher);
        record.decision.verdict.as_str().hash(hasher);
        record.decision.confidence.to_bits().hash(hasher);
        record.decision.rationale.hash(hasher);
        hash_debug(&record.decision.author, hasher);
        hash_debug(&record.triage_verdict, hasher);
        record.created_at.hash(hasher);
    }
}

fn hash_threat_doc(doc: Option<&serde_json::Value>, hasher: &mut DefaultHasher) {
    match doc {
        Some(value) => {
            true.hash(hasher);
            serde_json::to_string(value)
                .unwrap_or_else(|_| format!("{value:?}"))
                .hash(hasher);
        }
        None => false.hash(hasher),
    }
}

fn hash_debug(value: &impl std::fmt::Debug, hasher: &mut DefaultHasher) {
    format!("{value:?}").hash(hasher);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{DfdKind, DfdNodeModel, ModuleRisk};
    use kuzushi_core::Severity;

    fn finding(path: &str, severity: Severity) -> Finding {
        let mut finding = Finding::new_semgrep("rule", path, 1, None, severity, "title");
        finding.fingerprint = format!("{path}:{severity:?}");
        finding
    }

    #[test]
    fn visible_findings_cache_key_changes_when_projection_fields_change() {
        let mut findings = vec![finding("src/a.rs", Severity::High)];
        let original = VisibleFindingsCacheKey::from_app_parts(&findings, &[], None, None, None);

        findings[0].severity = Severity::Critical;
        let changed = VisibleFindingsCacheKey::from_app_parts(&findings, &[], None, None, None);

        assert_ne!(original, changed);
    }

    #[test]
    fn visible_findings_cache_key_tracks_review_binding_fields() {
        let mut findings = vec![finding("src/a.rs", Severity::High)];
        let original = VisibleFindingsCacheKey::from_app_parts(&findings, &[], None, None, None);

        findings[0].id = Some(41);
        let with_id = VisibleFindingsCacheKey::from_app_parts(&findings, &[], None, None, None);
        assert_ne!(original, with_id);

        findings[0].identity_id = Some("fi_review_identity".to_string());
        let with_identity =
            VisibleFindingsCacheKey::from_app_parts(&findings, &[], None, None, None);
        assert_ne!(with_id, with_identity);

        findings[0].created_at = "2026-07-10T00:00:00Z".to_string();
        let with_timestamp =
            VisibleFindingsCacheKey::from_app_parts(&findings, &[], None, None, None);
        assert_ne!(with_identity, with_timestamp);
    }

    #[test]
    fn risk_cache_key_ignores_unrelated_finding_text() {
        let mut findings = vec![finding("src/a.rs", Severity::High)];
        let original = RiskByModuleCacheKey::from_findings(&findings);

        findings[0].message = "new wording".to_string();
        let unchanged = RiskByModuleCacheKey::from_findings(&findings);

        assert_eq!(original, unchanged);
    }

    #[test]
    fn visible_findings_cache_reuses_only_matching_version() {
        let mut cache = ViewModelFragmentCache::default();
        let mut findings = vec![finding("src/a.rs", Severity::High)];
        let key = VisibleFindingsCacheKey::from_app_parts(&findings, &[], None, None, None);
        let projected = vec![VisibleFindingProjection {
            alias: "F-0001".to_string(),
            finding: findings[0].clone(),
        }];
        cache.cache_visible_findings(key.clone(), projected.clone());

        assert_eq!(cache.visible_findings(&key), Some(projected));
        findings[0].severity = Severity::Critical;
        let stale_key = VisibleFindingsCacheKey::from_app_parts(&findings, &[], None, None, None);
        assert!(cache.visible_findings(&stale_key).is_none());
    }

    #[test]
    fn risk_by_module_cache_reuses_only_matching_version() {
        let mut cache = ViewModelFragmentCache::default();
        let mut findings = vec![finding("src/a.rs", Severity::High)];
        let key = RiskByModuleCacheKey::from_findings(&findings);
        let risk = RiskByModule {
            modules: vec![ModuleRisk {
                module: "src".to_string(),
                counts: [0, 1, 0, 0, 0],
                score: 5.0,
            }],
        };
        cache.cache_risk_by_module(key.clone(), risk.clone());

        assert_eq!(cache.risk_by_module(&key), Some(risk));
        findings[0].severity = Severity::Critical;
        let stale_key = RiskByModuleCacheKey::from_findings(&findings);
        assert!(cache.risk_by_module(&stale_key).is_none());
    }

    #[test]
    fn dfd_model_cache_reuses_only_matching_threat_doc_version() {
        let mut cache = ViewModelFragmentCache::default();
        let mut doc = serde_json::json!({
            "dfd": {
                "nodes": [{ "name": "api", "zone": "app", "kind": "process" }],
                "flows": []
            }
        });
        let key = DfdModelCacheKey::from_threat_doc(Some(&doc));
        let model = DfdModel {
            nodes: vec![DfdNodeModel {
                name: "api".to_string(),
                zone: "app".to_string(),
                kind: DfdKind::Process,
            }],
            ..Default::default()
        };
        cache.cache_dfd_model(key.clone(), model.clone());

        assert_eq!(cache.dfd_model(&key), Some(model));
        doc["dfd"]["nodes"][0]["name"] = serde_json::json!("worker");
        let stale_key = DfdModelCacheKey::from_threat_doc(Some(&doc));
        assert!(cache.dfd_model(&stale_key).is_none());
    }
}
