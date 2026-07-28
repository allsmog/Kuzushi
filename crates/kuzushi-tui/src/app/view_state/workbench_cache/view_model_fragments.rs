use crate::ui_view_models::{DfdModel, ReviewFacetGroup, ReviewQueueRow, RiskByModule};
use kuzushi_core::Finding;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

#[derive(Debug, Default)]
pub(super) struct ViewModelFragmentCache {
    visible_findings: Option<CachedVisibleFindings>,
    review_queue: Option<CachedReviewQueue>,
    risk_by_module: Option<CachedRiskByModule>,
    dfd_model: Option<CachedDfdModel>,
}

impl ViewModelFragmentCache {
    pub(super) fn visible_findings(
        &self,
        key: &VisibleFindingsCacheKey,
    ) -> Option<Arc<[VisibleFindingProjection]>> {
        self.visible_findings
            .as_ref()
            .filter(|cache| &cache.key == key)
            .map(|cache| Arc::clone(&cache.projected))
    }

    pub(super) fn cache_visible_findings(
        &mut self,
        key: VisibleFindingsCacheKey,
        projected: Arc<[VisibleFindingProjection]>,
        before_search: Arc<[VisibleFindingProjection]>,
    ) {
        self.visible_findings = Some(CachedVisibleFindings {
            key,
            projected,
            before_search,
        });
    }

    pub(super) fn visible_findings_before_search(
        &self,
        key: &VisibleFindingsCacheKey,
    ) -> Option<Arc<[VisibleFindingProjection]>> {
        self.visible_findings
            .as_ref()
            .filter(|cache| &cache.key == key)
            .map(|cache| Arc::clone(&cache.before_search))
    }

    pub(super) fn invalidate_visible_findings(&mut self) {
        self.visible_findings = None;
        self.review_queue = None;
    }

    pub(super) fn review_queue(
        &self,
        key: &ReviewQueueCacheKey,
    ) -> Option<(Arc<[ReviewQueueRow]>, usize, usize, Arc<[ReviewFacetGroup]>)> {
        self.review_queue
            .as_ref()
            .filter(|cache| &cache.key == key)
            .map(|cache| {
                (
                    Arc::clone(&cache.rows),
                    cache.open_count,
                    cache.complete_count,
                    Arc::clone(&cache.facet_groups),
                )
            })
    }

    pub(super) fn cache_review_queue(
        &mut self,
        key: ReviewQueueCacheKey,
        rows: Arc<[ReviewQueueRow]>,
        open_count: usize,
        complete_count: usize,
        facet_groups: Arc<[ReviewFacetGroup]>,
    ) {
        self.review_queue = Some(CachedReviewQueue {
            key,
            rows,
            open_count,
            complete_count,
            facet_groups,
        });
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
    search_query: Option<String>,
}

impl VisibleFindingsCacheKey {
    pub(crate) fn from_app_parts(
        findings_revision: u64,
        review_decisions_revision: u64,
        target_base: Option<String>,
        active_component: Option<String>,
        active_filter: Option<String>,
        search_query: Option<String>,
    ) -> Self {
        Self {
            findings: ViewModelVersion(findings_revision),
            review_decisions: ViewModelVersion(review_decisions_revision),
            target_base,
            active_component,
            active_filter,
            search_query,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RiskByModuleCacheKey {
    findings: ViewModelVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReviewQueueCacheKey {
    visible_findings: VisibleFindingsCacheKey,
    mode: u8,
}

impl ReviewQueueCacheKey {
    pub(crate) fn new(visible_findings: VisibleFindingsCacheKey, mode: u8) -> Self {
        Self {
            visible_findings,
            mode,
        }
    }
}

impl RiskByModuleCacheKey {
    pub(crate) fn from_findings_revision(findings_revision: u64) -> Self {
        Self {
            findings: ViewModelVersion(findings_revision),
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
    projected: Arc<[VisibleFindingProjection]>,
    before_search: Arc<[VisibleFindingProjection]>,
}

#[derive(Debug)]
struct CachedReviewQueue {
    key: ReviewQueueCacheKey,
    rows: Arc<[ReviewQueueRow]>,
    open_count: usize,
    complete_count: usize,
    facet_groups: Arc<[ReviewFacetGroup]>,
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
    fn from_threat_doc(doc: Option<&serde_json::Value>) -> Self {
        version_from(|hasher| hash_threat_doc(doc, hasher))
    }
}

fn version_from(hash: impl FnOnce(&mut DefaultHasher)) -> ViewModelVersion {
    let mut hasher = DefaultHasher::new();
    hash(&mut hasher);
    ViewModelVersion(hasher.finish())
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
    fn visible_findings_cache_key_tracks_findings_revision() {
        let original = VisibleFindingsCacheKey::from_app_parts(7, 3, None, None, None, None);
        let changed = VisibleFindingsCacheKey::from_app_parts(8, 3, None, None, None, None);

        assert_ne!(original, changed);
    }

    #[test]
    fn visible_findings_cache_key_tracks_review_revision() {
        let original = VisibleFindingsCacheKey::from_app_parts(7, 3, None, None, None, None);
        let changed = VisibleFindingsCacheKey::from_app_parts(7, 4, None, None, None, None);

        assert_ne!(original, changed);
    }

    #[test]
    fn visible_findings_cache_key_tracks_every_search_edit() {
        let original = VisibleFindingsCacheKey::from_app_parts(
            7,
            3,
            None,
            None,
            None,
            Some("gate".to_string()),
        );
        let edited = VisibleFindingsCacheKey::from_app_parts(
            7,
            3,
            None,
            None,
            None,
            Some("gateway".to_string()),
        );
        let cleared = VisibleFindingsCacheKey::from_app_parts(7, 3, None, None, None, None);

        assert_ne!(original, edited);
        assert_ne!(edited, cleared);
    }

    #[test]
    fn risk_cache_key_tracks_findings_revision() {
        let original = RiskByModuleCacheKey::from_findings_revision(11);
        let changed = RiskByModuleCacheKey::from_findings_revision(12);

        assert_ne!(original, changed);
    }

    #[test]
    fn visible_findings_cache_reuses_only_matching_version() {
        let mut cache = ViewModelFragmentCache::default();
        let finding = finding("src/a.rs", Severity::High);
        let key = VisibleFindingsCacheKey::from_app_parts(1, 1, None, None, None, None);
        let projected: Arc<[VisibleFindingProjection]> = vec![VisibleFindingProjection {
            alias: "F-0001".to_string(),
            finding,
        }]
        .into();
        cache.cache_visible_findings(key.clone(), Arc::clone(&projected), Arc::clone(&projected));

        let first_hit = cache.visible_findings(&key).expect("cached projection");
        let second_hit = cache.visible_findings(&key).expect("cached projection");
        assert!(Arc::ptr_eq(&projected, &first_hit));
        assert!(Arc::ptr_eq(&first_hit, &second_hit));
        let stale_key = VisibleFindingsCacheKey::from_app_parts(2, 1, None, None, None, None);
        assert!(cache.visible_findings(&stale_key).is_none());
    }

    #[test]
    fn risk_by_module_cache_reuses_only_matching_version() {
        let mut cache = ViewModelFragmentCache::default();
        let key = RiskByModuleCacheKey::from_findings_revision(1);
        let risk = RiskByModule {
            modules: vec![ModuleRisk {
                module: "src".to_string(),
                counts: [0, 1, 0, 0, 0],
                score: 5.0,
            }],
        };
        cache.cache_risk_by_module(key.clone(), risk.clone());

        assert_eq!(cache.risk_by_module(&key), Some(risk));
        let stale_key = RiskByModuleCacheKey::from_findings_revision(2);
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
                key: "api".to_string(),
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
