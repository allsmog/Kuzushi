use super::*;

impl InventoryBuilder {
    pub(crate) fn add_source_file(&mut self, path: &str, language: &str, bytes: u64) {
        let language_accumulator = self.languages.entry(language.to_string()).or_default();
        language_accumulator.files += 1;
        language_accumulator.bytes += bytes;
        self.source_files.insert(
            path.to_string(),
            InventorySourceFile {
                path: path.to_string(),
                language: language.to_string(),
            },
        );
    }

    pub(crate) fn add_manifest(&mut self, path: &str, kind: &str) {
        self.manifests.insert(
            path.to_string(),
            InventoryFile {
                path: path.to_string(),
                kind: kind.to_string(),
            },
        );
    }

    pub(crate) fn add_dependency_manifest(&mut self, path: &str, kind: &str) {
        self.dependency_manifests.insert(
            path.to_string(),
            InventoryFile {
                path: path.to_string(),
                kind: kind.to_string(),
            },
        );
    }

    pub(crate) fn add_config_file(&mut self, path: &str, kind: &str) {
        self.config_files.insert(
            path.to_string(),
            InventoryFile {
                path: path.to_string(),
                kind: kind.to_string(),
            },
        );
    }

    pub(crate) fn add_framework(
        &mut self,
        name: &str,
        language: &str,
        evidence: impl Into<String>,
    ) {
        self.frameworks
            .entry((name.to_string(), language.to_string()))
            .or_default()
            .evidence
            .insert(evidence.into());
    }

    pub(crate) fn add_entrypoint(&mut self, kind: &str, path: &str, detail: &str) {
        let key = format!("{kind}:{path}:{detail}");
        self.entrypoints
            .entry(key)
            .or_insert_with(|| InventoryEntrypoint {
                kind: kind.to_string(),
                path: path.to_string(),
                detail: detail.to_string(),
            });
    }

    pub(crate) fn add_route_controller(&mut self, item: InventoryRouteController) {
        let key = format!(
            "{}:{}:{:?}:{:?}:{:?}",
            item.kind, item.path, item.line, item.method, item.route
        );
        self.routes_controllers.entry(key).or_insert(item);
    }

    pub(crate) fn add_generated_vendor_path(&mut self, item: InventoryPathClassification) {
        self.generated_vendor_paths
            .entry(item.path.clone())
            .or_insert(item);
    }

    pub(crate) fn finish(
        self,
        root_name: String,
        truncation: Option<InventoryTruncation>,
    ) -> RepositoryInventory {
        RepositoryInventory {
            root_name,
            truncation,
            languages: self
                .languages
                .into_iter()
                .map(|(name, accumulator)| InventoryLanguage {
                    name,
                    files: accumulator.files,
                    bytes: accumulator.bytes,
                })
                .collect(),
            source_files: self.source_files.into_values().collect(),
            manifests: self.manifests.into_values().collect(),
            dependency_manifests: self.dependency_manifests.into_values().collect(),
            config_files: self.config_files.into_values().collect(),
            frameworks: self
                .frameworks
                .into_iter()
                .map(|((name, language), accumulator)| InventoryFramework {
                    name,
                    language,
                    evidence: accumulator.evidence.into_iter().collect(),
                })
                .collect(),
            entrypoints: self.entrypoints.into_values().collect(),
            routes_controllers: self.routes_controllers.into_values().collect(),
            generated_vendor_paths: self.generated_vendor_paths.into_values().collect(),
        }
    }
}
