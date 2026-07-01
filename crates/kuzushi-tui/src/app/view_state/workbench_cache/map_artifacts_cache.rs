use crate::app::{PlanningTaskId, WorkflowPhase};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAP_ARTIFACT_TTL: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
pub(super) struct MapArtifactsCache {
    cached: Option<CachedMapArtifacts>,
}

impl MapArtifactsCache {
    pub(super) fn built(&mut self, target: Option<&Path>) -> bool {
        let Some(target) = target else {
            return false;
        };
        let now = Instant::now();
        if let Some(cache) = self
            .cached
            .as_ref()
            .filter(|cache| cache.target == target && cache.fresh_at(now))
        {
            return cache.built;
        }
        let built = map_artifact_exists(target);
        self.cached = Some(CachedMapArtifacts {
            target: target.to_path_buf(),
            cached_at: now,
            built,
        });
        built
    }

    pub(super) fn invalidate(&mut self) {
        self.cached = None;
    }
}

#[derive(Debug)]
struct CachedMapArtifacts {
    target: PathBuf,
    cached_at: Instant,
    built: bool,
}

impl CachedMapArtifacts {
    fn fresh_at(&self, now: Instant) -> bool {
        now.duration_since(self.cached_at) <= MAP_ARTIFACT_TTL
    }
}

fn map_artifact_exists(target: &Path) -> bool {
    PlanningTaskId::in_phase(WorkflowPhase::Map)
        .into_iter()
        .filter_map(PlanningTaskId::artifact_relative_path)
        .any(|relative| target.join(relative).exists())
}
