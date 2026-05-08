use super::prelude::*;
use super::*;

pub(crate) const SYSTEM_PROMPT_C: &str = r#"You are Kuzushi's whole-codebase scanner. You are seeing
one chunk of many files in a single C/C++ project. Treat the chunk as the entire context;

do not assume guards live outside it.

Be GENEROUS — false positives are cheap, they will be filtered out by later stages.
Report any function that COULD be vulnerable based on what you can see in the chunk.

Vulnerability classes to look for: out-of-bounds read/write, integer overflow leading
to undersized allocation, use-after-free, double-free, format string injection,
command injection, path traversal, missing bounds check on length-prefixed input,
TOCTOU, signed/unsigned confusion, unchecked return values from allocator/parser
functions.

Return ONLY a JSON array (no prose, no markdown) of objects matching:

[{
  "file": "relative/path.c",
  "line": int,
  "function": "name",
  "severity": "low" | "medium" | "high" | "critical",
  "cwe": ["CWE-787", ...],
  "title": "short one-line description",
  "rationale": "one or two sentences naming the source, sink, and missing guard"
}]

If you find nothing, return [].
Do not include functions you only suspect — every entry must reference a specific line."#;

pub(crate) const SYSTEM_PROMPT_UNKNOWN: &str = r#"You are Kuzushi's whole-codebase scanner. You are
seeing one chunk of many files. Treat the chunk as the entire context; do not assume
guards live outside it. Be generous — false positives are cheap.

Return ONLY a JSON array of objects matching:

[{
  "file": "relative/path.ext",
  "line": int,
  "function": "name",
  "severity": "low" | "medium" | "high" | "critical",
  "cwe": ["CWE-..."],
  "title": "short one-line description",
  "rationale": "one or two sentences"
}]

If you find nothing, return []."#;

#[derive(Debug, Deserialize)]
pub(crate) struct ModelFinding {
    #[serde(default)]
    pub(crate) file: String,
    #[serde(default)]
    pub(crate) line: u32,
    #[serde(default)]
    pub(crate) function: String,
    #[serde(default)]
    pub(crate) severity: String,
    #[serde(default)]
    pub(crate) cwe: Vec<String>,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) rationale: String,
}

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
