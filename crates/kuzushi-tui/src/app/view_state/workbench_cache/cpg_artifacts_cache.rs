use std::path::{Path, PathBuf};

/// Memoizes whether the target has usable whole-graph cpg-rs artifacts for the
/// current shape version (`cpg_has_artifacts`). The health view reads this
/// cached flag instead of running `std::fs::read_dir` on the render path.
#[derive(Debug, Default)]
pub(super) struct CpgArtifactsCache {
    cached: Option<CachedCpgArtifacts>,
}

impl CpgArtifactsCache {
    pub(super) fn cached(&self, target: &Path) -> Option<bool> {
        self.cached
            .as_ref()
            .filter(|cache| cache.target == target)
            .map(|cache| cache.present)
    }

    pub(super) fn store(&mut self, target: PathBuf, present: bool) {
        self.cached = Some(CachedCpgArtifacts { target, present });
    }

    pub(super) fn invalidate(&mut self) {
        self.cached = None;
    }
}

#[derive(Debug)]
struct CachedCpgArtifacts {
    target: PathBuf,
    present: bool,
}
