use std::path::{Path, PathBuf};

pub const THREAT_INTEL_CATALOGS_DIR: &str = "catalogs";
pub const HARVESTED_THREAT_INTEL_CATALOG_FILE: &str = "harvested.toml";

pub fn threat_intel_catalogs_dir(root: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_root(root).join(THREAT_INTEL_CATALOGS_DIR)
}

pub fn harvested_threat_intel_catalog_path(root: impl AsRef<Path>) -> PathBuf {
    threat_intel_catalogs_dir(root).join(HARVESTED_THREAT_INTEL_CATALOG_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_intel_catalog_paths_use_workspace_state_root() {
        let root = Path::new("/repo");
        let state_root = crate::workspace::workspace_state_root(root);

        assert_eq!(
            threat_intel_catalogs_dir(root),
            state_root.join(THREAT_INTEL_CATALOGS_DIR)
        );
        assert_eq!(
            harvested_threat_intel_catalog_path(root),
            state_root
                .join(THREAT_INTEL_CATALOGS_DIR)
                .join(HARVESTED_THREAT_INTEL_CATALOG_FILE)
        );
    }
}
