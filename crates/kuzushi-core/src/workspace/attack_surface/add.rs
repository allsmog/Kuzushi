use super::*;

#[derive(Debug, Clone)]
pub(crate) struct AttackSurfaceDraft {
    pub(crate) kind: AttackSurfaceKind,
    pub(crate) path: String,
    pub(crate) line: Option<u32>,
    pub(crate) language: String,
    pub(crate) framework: Option<String>,
    pub(crate) title: String,
    pub(crate) evidence: String,
    pub(crate) method: Option<String>,
    pub(crate) route: Option<String>,
    pub(crate) boundary: Option<String>,
    pub(crate) metadata: Value,
}

#[derive(Debug, Default)]
pub(crate) struct AttackSurfaceBuilder {
    pub(crate) surfaces: BTreeMap<String, AttackSurface>,
}

impl AttackSurfaceBuilder {
    pub(crate) fn add(&mut self, draft: AttackSurfaceDraft) {
        let surface = AttackSurface::from_draft(draft);
        self.surfaces.entry(surface.id.clone()).or_insert(surface);
    }

    pub(crate) fn finish(self, root_name: String) -> AttackSurfaceMap {
        let surfaces = rank_attack_surfaces(self.surfaces.into_values().collect());
        AttackSurfaceMap {
            root_name,
            summary: summarize_surfaces(&surfaces),
            surfaces,
        }
    }
}

pub fn build_attack_surface_map(root: impl AsRef<Path>) -> Result<AttackSurfaceMap> {
    let inventory = build_repository_inventory(root.as_ref())?;
    build_attack_surface_map_from_inventory(root, &inventory)
}

pub fn build_attack_surface_map_from_inventory(
    root: impl AsRef<Path>,
    inventory: &RepositoryInventory,
) -> Result<AttackSurfaceMap> {
    let root = root
        .as_ref()
        .canonicalize()
        .with_context(|| format!("repository root {} does not exist", root.as_ref().display()))?;
    if !root.is_dir() {
        anyhow::bail!("repository root {} is not a directory", root.display());
    }

    let mut builder = AttackSurfaceBuilder::default();
    add_inventory_surfaces(&mut builder, inventory);
    for source_file in &inventory.source_files {
        inspect_source_file(&root, source_file, &mut builder)?;
    }

    Ok(builder.finish(inventory.root_name.clone()))
}

pub(crate) fn add_inventory_surfaces(
    builder: &mut AttackSurfaceBuilder,
    inventory: &RepositoryInventory,
) {
    for route in &inventory.routes_controllers {
        if route.kind == "route" {
            add_route_surface(builder, route);
        }
    }

    for entrypoint in &inventory.entrypoints {
        builder.add(AttackSurfaceDraft {
            kind: AttackSurfaceKind::CliEntrypoint,
            path: entrypoint.path.clone(),
            line: None,
            language: language_from_path(&entrypoint.path)
                .unwrap_or("Unknown")
                .to_string(),
            framework: None,
            title: format!("Entrypoint: {}", entrypoint.kind),
            evidence: entrypoint.detail.clone(),
            method: None,
            route: None,
            boundary: Some("process_entrypoint".to_string()),
            metadata: json!({
                "source": "repository_inventory",
                "entrypointKind": entrypoint.kind,
            }),
        });
    }
}

pub(crate) fn add_route_surface(
    builder: &mut AttackSurfaceBuilder,
    route: &InventoryRouteController,
) {
    let method = route.method.clone().unwrap_or_else(|| "ANY".to_string());
    let Some(route_path) = route.route.clone() else {
        return;
    };
    for method in inventory_route_methods(route, &method) {
        add_route_method_surface(builder, route, &method, &route_path);
    }
}

fn inventory_route_methods(route: &InventoryRouteController, method: &str) -> Vec<String> {
    if route.framework.as_deref() != Some("ASP.NET Core") || !method.contains(',') {
        return vec![method.to_string()];
    }
    method
        .split(',')
        .map(str::trim)
        .filter(|method| !method.is_empty())
        .map(str::to_string)
        .collect()
}

fn add_route_method_surface(
    builder: &mut AttackSurfaceBuilder,
    route: &InventoryRouteController,
    method: &str,
    route_path: &str,
) {
    builder.add(AttackSurfaceDraft {
        kind: AttackSurfaceKind::HttpRoute,
        path: route.path.clone(),
        line: route.line,
        language: language_from_path(&route.path)
            .unwrap_or("Unknown")
            .to_string(),
        framework: route.framework.clone(),
        title: format!("{method} {route_path}"),
        evidence: route.detail.clone(),
        method: Some(method.to_string()),
        route: Some(route_path.to_string()),
        boundary: Some("public_http".to_string()),
        metadata: json!({ "source": "repository_inventory" }),
    });
}
