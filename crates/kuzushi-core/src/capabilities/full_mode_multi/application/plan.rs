use super::walk_files::walk_files;
use crate::capabilities::full_mode_multi::domain::{ChunkPlan, FullModeConfig, FullModePlan};
use anyhow::Result;

pub fn plan(cfg: &FullModeConfig) -> Result<FullModePlan> {
    let mut files = walk_files(cfg)?;
    files.sort_by(|a, b| a.path.cmp(&b.path)); // directory affinity
    let mut chunks: Vec<ChunkPlan> = Vec::new();
    let mut current = ChunkPlan {
        id: 0,
        files: Vec::new(),
        est_tokens: 0,
    };
    let cap = cfg.max_tokens_per_chunk;
    let mut total_files = 0usize;
    let mut total_bytes = 0usize;
    let mut total_tokens = 0usize;
    for f in files {
        total_files += 1;
        total_bytes += f.bytes;
        total_tokens += f.est_tokens;
        if !current.files.is_empty() && current.est_tokens + f.est_tokens > cap {
            chunks.push(std::mem::replace(
                &mut current,
                ChunkPlan {
                    id: chunks.len() as u32 + 1,
                    files: Vec::new(),
                    est_tokens: 0,
                },
            ));
        }
        current.est_tokens += f.est_tokens;
        current.files.push(f);
    }
    if !current.files.is_empty() {
        chunks.push(current);
    }
    // Renumber from 0 for stable ids.
    for (i, c) in chunks.iter_mut().enumerate() {
        c.id = i as u32;
    }
    Ok(FullModePlan {
        chunks,
        total_files,
        total_bytes,
        total_tokens,
    })
}
