use super::walk_files::walk_files;
use crate::capabilities::full_mode_multi::domain::{
    ChunkPlan, FileBucket, FullModeConfig, FullModePlan,
};
use anyhow::Result;

pub fn plan(cfg: &FullModeConfig) -> Result<FullModePlan> {
    plan_with_observer(cfg, &mut |_| {}, &|| false)
}

pub(crate) fn plan_with_observer(
    cfg: &FullModeConfig,
    progress: &mut dyn FnMut(usize),
    canceled: &dyn Fn() -> bool,
) -> Result<FullModePlan> {
    let planned = walk_files(cfg, progress, canceled)?;
    let mut files = planned.files;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let plan = FullModePlan {
        total_files: files.len(),
        total_bytes: files.iter().map(|file| file.bytes).sum(),
        total_tokens: files.iter().map(|file| file.est_tokens).sum(),
        chunks: group_chunks(files, cfg.max_tokens_per_chunk),
        coverage: Some(planned.coverage),
    };
    validate_retry_selection(&plan, cfg.failed_chunk_ids.as_deref())?;
    Ok(plan)
}

fn group_chunks(files: Vec<FileBucket>, cap: usize) -> Vec<ChunkPlan> {
    let mut chunks = Vec::new();
    let mut current = empty_chunk(0);
    for file in files {
        if !current.files.is_empty() && current.est_tokens + file.est_tokens > cap {
            let next = empty_chunk(chunks.len() as u32 + 1);
            chunks.push(std::mem::replace(&mut current, next));
        }
        current.est_tokens += file.est_tokens;
        current.files.push(file);
    }
    if !current.files.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn empty_chunk(id: u32) -> ChunkPlan {
    ChunkPlan {
        id,
        files: Vec::new(),
        est_tokens: 0,
    }
}

fn validate_retry_selection(plan: &FullModePlan, ids: Option<&[u32]>) -> Result<()> {
    let Some(ids) = ids else {
        return Ok(());
    };
    anyhow::ensure!(
        !ids.is_empty(),
        "retry selection is empty; select known chunk IDs before planning work"
    );
    let unknown = ids
        .iter()
        .filter(|id| **id as usize >= plan.chunks.len())
        .collect::<Vec<_>>();
    anyhow::ensure!(unknown.is_empty(), "retry chunk IDs are absent from this plan: {unknown:?}; replan after source changes. No model request started.");
    Ok(())
}

pub(crate) fn selected_plan(plan: &FullModePlan, ids: Option<&[u32]>) -> FullModePlan {
    let chunks = plan
        .chunks
        .iter()
        .filter(|chunk| ids.is_none_or(|ids| ids.contains(&chunk.id)))
        .cloned()
        .collect::<Vec<_>>();
    FullModePlan {
        coverage: plan.coverage.clone(),
        total_files: chunks.iter().map(|chunk| chunk.files.len()).sum(),
        total_bytes: chunks
            .iter()
            .flat_map(|chunk| &chunk.files)
            .map(|file| file.bytes)
            .sum(),
        total_tokens: chunks.iter().map(|chunk| chunk.est_tokens).sum(),
        chunks,
    }
}
