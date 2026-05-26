use std::path::{Path, PathBuf};

pub(crate) const TAINT_IRIS_NEXT_JOERN_CPG_FILE: &str = "cpg.bin";
pub(crate) const TAINT_IRIS_NEXT_DISCOVERED_SIGNALS_FILE: &str = "discovered-signals.json";
pub(crate) const TAINT_IRIS_NEXT_TARGET_CATALOG_FILE: &str = "taint-iris-next-catalog.json";
pub(crate) const TAINT_IRIS_NEXT_CODEQL_BUILD_SCRIPT_FILE: &str = "codeql-build.sh";

pub(crate) fn taint_iris_next_joern_cpg_path(target: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(TAINT_IRIS_NEXT_JOERN_CPG_FILE)
}

pub(crate) fn taint_iris_next_discovered_signals_path(target: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(TAINT_IRIS_NEXT_DISCOVERED_SIGNALS_FILE)
}

pub(crate) fn taint_iris_next_target_catalog_artifact_path(target: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(TAINT_IRIS_NEXT_TARGET_CATALOG_FILE)
}

pub(crate) fn taint_iris_next_codeql_build_script_path(target: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(TAINT_IRIS_NEXT_CODEQL_BUILD_SCRIPT_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_iris_next_artifact_paths_use_workspace_state_root() {
        let target = Path::new("/repo");
        let state_root = crate::workspace::workspace_state_root(target);

        assert_eq!(
            taint_iris_next_joern_cpg_path(target),
            state_root.join(TAINT_IRIS_NEXT_JOERN_CPG_FILE)
        );
        assert_eq!(
            taint_iris_next_discovered_signals_path(target),
            state_root.join(TAINT_IRIS_NEXT_DISCOVERED_SIGNALS_FILE)
        );
        assert_eq!(
            taint_iris_next_target_catalog_artifact_path(target),
            state_root.join(TAINT_IRIS_NEXT_TARGET_CATALOG_FILE)
        );
        assert_eq!(
            taint_iris_next_codeql_build_script_path(target),
            state_root.join(TAINT_IRIS_NEXT_CODEQL_BUILD_SCRIPT_FILE)
        );
    }
}
