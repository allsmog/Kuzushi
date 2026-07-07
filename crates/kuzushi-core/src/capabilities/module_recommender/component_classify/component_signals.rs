use super::super::*;
use crate::attack_surface::{AttackSurface, AttackSurfaceKind};
use crate::workspace::NestedProjectScope;
use std::collections::BTreeSet;

#[derive(Debug, Default)]
pub(super) struct ComponentSignals {
    pub(super) source_files: usize,
    pub(super) manifests: usize,
    pub(super) dependency_manifests: usize,
    pub(super) iac_files: usize,
    pub(super) entrypoints: usize,
    pub(super) routes: usize,
    pub(super) high_risk_surfaces: usize,
    pub(super) max_risk_score: u16,
    pub(super) languages: BTreeSet<String>,
    pub(super) frameworks: BTreeSet<String>,
    pub(super) surface_kinds: BTreeSet<AttackSurfaceKind>,
}

impl ComponentSignals {
    pub(super) fn for_scope(
        scope: &NestedProjectScope,
        inventory: &RepositoryInventory,
        attack_surface: &AttackSurfaceMap,
    ) -> Self {
        let mut signals = Self::default();
        signals.absorb_inventory(scope, inventory);
        signals.absorb_attack_surface(scope, attack_surface);
        signals
    }

    pub(super) fn has_web_stack(&self) -> bool {
        self.routes > 0
            && self
                .languages
                .iter()
                .any(|language| matches!(language.as_str(), "JavaScript" | "TypeScript"))
    }

    pub(super) fn has_service_surface(&self) -> bool {
        self.routes > 0
            || self.surface_kinds.iter().any(|kind| {
                matches!(
                    kind,
                    AttackSurfaceKind::HttpRoute | AttackSurfaceKind::RpcHandler
                )
            })
    }

    pub(super) fn risk_score(&self) -> u16 {
        let structural = (self.routes as u16 * 8)
            .saturating_add(self.entrypoints as u16 * 5)
            .saturating_add(self.high_risk_surfaces as u16 * 10)
            .min(40);
        self.max_risk_score.saturating_add(structural).min(100)
    }

    fn absorb_inventory(&mut self, scope: &NestedProjectScope, inventory: &RepositoryInventory) {
        self.source_files = inventory
            .source_files
            .iter()
            .filter(|file| path_in_scope(&file.path, &scope.rel_path))
            .inspect(|file| {
                self.languages.insert(file.language.clone());
            })
            .count();
        self.manifests = count_paths_in_scope(&inventory.manifests, &scope.rel_path);
        self.dependency_manifests =
            count_paths_in_scope(&inventory.dependency_manifests, &scope.rel_path);
        self.iac_files = inventory
            .config_files
            .iter()
            .filter(|file| {
                path_in_scope(&file.path, &scope.rel_path)
                    && matches!(file.kind.as_str(), "compose" | "dockerfile" | "terraform")
            })
            .count();
        self.entrypoints = inventory
            .entrypoints
            .iter()
            .filter(|entrypoint| path_in_scope(&entrypoint.path, &scope.rel_path))
            .count();
        self.routes = inventory
            .routes_controllers
            .iter()
            .filter(|route| path_in_scope(&route.path, &scope.rel_path))
            .count();
        self.absorb_frameworks(scope, inventory);
    }

    fn absorb_frameworks(&mut self, scope: &NestedProjectScope, inventory: &RepositoryInventory) {
        for framework in &inventory.frameworks {
            if framework
                .evidence
                .iter()
                .any(|path| path_in_scope(path, &scope.rel_path))
            {
                self.frameworks.insert(framework.name.clone());
            }
        }
    }

    fn absorb_attack_surface(
        &mut self,
        scope: &NestedProjectScope,
        attack_surface: &AttackSurfaceMap,
    ) {
        for surface in attack_surface
            .surfaces
            .iter()
            .filter(|surface| path_in_scope(&surface.path, &scope.rel_path))
        {
            self.absorb_surface(surface);
        }
    }

    fn absorb_surface(&mut self, surface: &AttackSurface) {
        self.surface_kinds.insert(surface.kind);
        self.max_risk_score = self.max_risk_score.max(surface.risk.score);
        if matches!(surface.risk.tier.as_str(), "high" | "critical") {
            self.high_risk_surfaces += 1;
        }
    }
}

fn count_paths_in_scope(
    files: &[crate::repository_inventory::InventoryFile],
    scope: &str,
) -> usize {
    files
        .iter()
        .filter(|file| path_in_scope(&file.path, scope))
        .count()
}

fn path_in_scope(path: &str, scope: &str) -> bool {
    let scope = scope.trim_matches('/');
    if scope == "." || scope.is_empty() {
        return true;
    }
    path == scope
        || path
            .strip_prefix(scope)
            .is_some_and(|rest| rest.starts_with('/'))
}
