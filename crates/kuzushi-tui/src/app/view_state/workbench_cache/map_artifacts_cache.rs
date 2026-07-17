use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub(super) struct MapArtifactsCache {
    cached: Option<CachedMapArtifacts>,
}

impl MapArtifactsCache {
    pub(super) fn cached(&self, target: &Path) -> Option<bool> {
        self.cached
            .as_ref()
            .filter(|cache| cache.target == target)
            .map(|cache| cache.built)
    }

    pub(super) fn store(&mut self, target: PathBuf, built: bool) {
        self.cached = Some(CachedMapArtifacts { target, built });
    }

    pub(super) fn invalidate(&mut self) {
        self.cached = None;
    }
}

#[derive(Debug)]
struct CachedMapArtifacts {
    target: PathBuf,
    built: bool,
}
