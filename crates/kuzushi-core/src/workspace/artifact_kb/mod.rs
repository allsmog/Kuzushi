use crate::run_artifacts::runs_root;
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
pub(crate) use discover_workspace_artifact_records::*;
pub(crate) use fnv1a_hex::*;
pub(crate) use infer_title::*;
pub(crate) use open::SourceSignature;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
mod discover_workspace_artifact_records;
mod fnv1a_hex;
mod from_text_source;
mod infer_title;
mod open;
mod refresh_workspace_artifacts;
mod render_prompt_block;
mod search_artifact_knowledge;
#[cfg(test)]
mod tests;

pub use from_text_source::ArtifactKnowledgeRecord;
pub use from_text_source::ArtifactSearchResult;
pub(crate) use refresh_workspace_artifacts::{
    index_artifact_sources, refresh_workspace_artifacts, ArtifactRefreshReport,
};
pub use render_prompt_block::artifact_kb_path;
pub use render_prompt_block::index_workspace_artifacts;
pub use render_prompt_block::ArtifactIndexReport;
pub use render_prompt_block::ArtifactKnowledgePromptContext;
pub use render_prompt_block::ArtifactKnowledgeSnippet;
pub use render_prompt_block::ArtifactSearchReport;
pub use render_prompt_block::StaleArtifactRecord;
pub use search_artifact_knowledge::artifact_knowledge_prompt_context;
pub use search_artifact_knowledge::search_artifact_knowledge;
pub use search_artifact_knowledge::ArtifactKnowledgeStore;
