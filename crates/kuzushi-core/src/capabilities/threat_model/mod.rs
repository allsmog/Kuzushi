use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::StructuredJsonContract;
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

mod adapters;
mod application;
mod domain;
#[cfg(test)]
mod normalize_document_tests;
mod persistence;
#[cfg(test)]
mod tests;

pub(crate) use adapters::*;
pub(crate) use application::*;
pub(crate) use domain::*;
pub(crate) use persistence::*;

pub use adapters::execute_threat_model_tool;
pub use application::{
    apply_threat_model_patch_revision, classify_scope_binding, current_scope_ref_for_path,
    ScopeBindingStatus, ThreatModelPatchCommit,
};
pub use domain::{security_context_link_report, SecurityContextLinkReport, ThreatModelBuildRoots};
pub use persistence::{
    activate_threat_model, adopt_threat_model_mirror_edits, commit_threat_model_revision,
    inspect_threat_model_mirror_diff, list_model_revisions, list_threat_model_heads,
    list_threat_model_versions, live_threat_model_sha256, load_active_threat_model,
    load_build_threat_model, load_persistent_threat_model, load_scope_threat_model,
    load_threat_model_manifest, load_threat_model_revision, open_writable_threat_model_store,
    persistent_threat_model_path, record_threat_model_version,
    record_threat_model_version_with_ref, resolve_threat_model, resolve_unique_build_lineage,
    restore_threat_model_revision, restore_threat_model_version, save_persistent_threat_model,
    threat_model_manifest_path, threat_model_object_path, threat_model_store_path,
    try_live_threat_model_sha256, try_load_persistent_threat_model, try_resolve_threat_model,
    ActivationSource, ActiveThreatModel, MirrorAction, ResolvedThreatModel, ScopeRef,
    ThreatModelActivation, ThreatModelCommit, ThreatModelCommitResult, ThreatModelId,
    ThreatModelJsonChange, ThreatModelManifest, ThreatModelMetadata, ThreatModelMirrorDiff,
    ThreatModelRef, ThreatModelResolvedVia, ThreatModelRevisionId, ThreatModelRevisionMetadata,
    ThreatModelRevisionSource, ThreatModelStoreError, ThreatModelVerificationCache,
};
