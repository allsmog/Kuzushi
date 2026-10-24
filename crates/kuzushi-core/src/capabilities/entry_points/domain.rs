use crate::attack_surface::AttackSurface;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;

pub(crate) const ENTRY_POINTS_FILE: &str = "entry-points.json";
pub(crate) const MAX_ENTRY_POINTS_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const ENTRY_POINT_SELECTION_POLICY: &str = "risk-kind-stratified-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EntryPointRecord {
    #[serde(flatten)]
    pub(crate) surface: AttackSurface,
    #[serde(default)]
    pub(crate) name: Value,
    #[serde(default)]
    pub(crate) location: Value,
    #[serde(flatten)]
    pub(crate) extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EntryPointCatalogProvenance {
    pub(crate) built_at_ms: u64,
    pub(crate) sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) revision_dirty: Option<bool>,
    pub(crate) context_snapshot_timestamp: u64,
    pub(crate) context_snapshot_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) context_snapshot_tree_hash: Option<String>,
}

/// How much of the target the context snapshot let the extractor see. A
/// snapshot that declared its own truncation still yields usable rows, but
/// only as a disclosed partial catalog: the rows it lacks were never in the
/// snapshot to extract.
///
/// `Unrecorded` is what an artifact carrying no coverage deserializes to.
/// Silence is not a completeness claim: the payload digest covers only the
/// rows, so a field an older writer never wrote — or one removed from a
/// partial catalog — would otherwise read as a catalog that saw everything.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "state", rename_all = "camelCase")]
pub(crate) enum EntryPointSnapshotCoverage {
    #[default]
    Unrecorded,
    Complete,
    #[serde(rename_all = "camelCase")]
    Partial {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        array_cap: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        omitted_entries: Option<u64>,
    },
}

impl EntryPointSnapshotCoverage {
    /// Positive observations can be used only with an explicit coverage record.
    /// They never establish absence outside that recorded snapshot.
    pub(crate) fn require_recorded(&self) -> anyhow::Result<()> {
        if matches!(self, Self::Unrecorded) {
            return self.require_complete();
        }
        Ok(())
    }

    pub(crate) fn is_partial(&self) -> bool {
        matches!(self, Self::Partial { .. })
    }

    /// One operator-facing line naming what this catalog cannot account for,
    /// or `None` when it records that the snapshot covered the whole target.
    pub(crate) fn disclosure(&self) -> Option<String> {
        match self {
            Self::Complete => None,
            Self::Unrecorded => {
                Some("the catalog records no snapshot coverage of its own".to_string())
            }
            Self::Partial {
                reason,
                array_cap,
                omitted_entries,
            } => Some(partial_disclosure(reason, *array_cap, *omitted_entries)),
        }
    }

    /// Refusal for consumers that ground on the catalog as the complete
    /// entry-point set, where partial rows would read as proven absence.
    pub(crate) fn require_complete(&self) -> anyhow::Result<()> {
        match self {
            Self::Complete => Ok(()),
            Self::Unrecorded => anyhow::bail!(
                "entry-point grounding requires a catalog that records the snapshot coverage it \
                 was built from; this one records none, so its rows cannot stand as the complete \
                 entry-point set — rebuild it with `entry-points:extract`"
            ),
            Self::Partial {
                reason,
                array_cap,
                omitted_entries,
            } => anyhow::bail!(
                "entry-point grounding requires a complete context snapshot, but {}; \
                 `entry-points:extract` still writes a partial catalog — ground on a narrower \
                 target root for complete coverage",
                partial_disclosure(reason, *array_cap, *omitted_entries)
            ),
        }
    }
}

fn partial_disclosure(reason: &str, array_cap: Option<u64>, omitted: Option<u64>) -> String {
    let mut text = format!("the context snapshot is truncated ({reason})");
    if let Some(omitted) = omitted {
        text.push_str(&format!(
            "; {omitted} snapshot entr{} omitted",
            plural(omitted)
        ));
    }
    if let Some(cap) = array_cap {
        text.push_str(&format!(" at the {cap}-entry array cap"));
    }
    text
}

fn plural(count: u64) -> &'static str {
    if count == 1 {
        "y"
    } else {
        "ies"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EntryPointCatalog {
    pub(crate) target: String,
    pub(crate) timestamp: u64,
    pub(crate) snapshot_timestamp: u64,
    pub(crate) total: usize,
    pub(crate) entry_points: Vec<EntryPointRecord>,
    pub(crate) provenance: EntryPointCatalogProvenance,
    /// Absent on catalogs written before coverage was recorded, which read as
    /// `Unrecorded` rather than as a claim of completeness.
    #[serde(default)]
    pub(crate) snapshot_coverage: EntryPointSnapshotCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextSnapshotIdentity {
    pub(crate) target: String,
    pub(crate) timestamp: u64,
    pub(crate) sha256: String,
    pub(crate) revision: Option<String>,
    pub(crate) revision_dirty: Option<bool>,
    pub(crate) tree_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ContextSnapshotDocument {
    pub(crate) value: Value,
    pub(crate) identity: ContextSnapshotIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntryPointCatalogReceipt {
    pub(crate) status: String,
    pub(crate) sha256: Option<String>,
    pub(crate) records: usize,
    pub(crate) records_selected: usize,
    pub(crate) grounding_limit: usize,
    pub(crate) grounding_records_selected: usize,
    pub(crate) snapshot_timestamp: Option<u64>,
    pub(crate) context_sha256: Option<String>,
    pub(crate) tree_hash: Option<String>,
    pub(crate) selection_policy: String,
    pub(crate) revision: Option<String>,
    pub(crate) revision_dirty: Option<bool>,
}

impl EntryPointCatalogReceipt {
    pub(crate) fn unavailable(status: &str) -> Self {
        Self {
            status: status.to_string(),
            sha256: None,
            records: 0,
            records_selected: 0,
            grounding_limit: 0,
            grounding_records_selected: 0,
            snapshot_timestamp: None,
            context_sha256: None,
            tree_hash: None,
            selection_policy: ENTRY_POINT_SELECTION_POLICY.to_string(),
            revision: None,
            revision_dirty: None,
        }
    }

    pub(crate) fn json(&self) -> Value {
        let mut value = json!({
            "status": self.status,
            "sha256": self.sha256,
            "records": self.records,
            "recordsSelected": self.records_selected,
            "groundingLimit": self.grounding_limit,
            "groundingRecordsSelected": self.grounding_records_selected,
            "snapshotTimestamp": self.snapshot_timestamp,
            "contextSha256": self.context_sha256,
            "treeHash": self.tree_hash,
            "selectionPolicy": self.selection_policy,
        });
        insert_optional_provenance(&mut value, self);
        value
    }
}

fn insert_optional_provenance(value: &mut Value, receipt: &EntryPointCatalogReceipt) {
    let Some(fields) = value.as_object_mut() else {
        return;
    };
    if let Some(revision) = receipt.revision.as_ref() {
        fields.insert("revision".to_string(), json!(revision));
    }
    if let Some(dirty) = receipt.revision_dirty {
        fields.insert("revisionDirty".to_string(), json!(dirty));
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EntryPointCatalogGrounding {
    pub(crate) receipt: EntryPointCatalogReceipt,
    pub(crate) catalog_ids: BTreeSet<String>,
    pub(crate) catalog_surfaces: Vec<crate::attack_surface::AttackSurface>,
}

impl EntryPointCatalogGrounding {
    pub(crate) fn unavailable(status: &str) -> Self {
        Self {
            receipt: EntryPointCatalogReceipt::unavailable(status),
            catalog_ids: BTreeSet::new(),
            catalog_surfaces: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EntryPointCatalogResolution {
    pub(crate) catalog: Option<EntryPointCatalog>,
    pub(crate) status: String,
    pub(crate) path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPointCatalogAuthentication {
    pub sha256: String,
    pub total: usize,
    pub snapshot_timestamp: u64,
    pub context_sha256: String,
    pub tree_hash: Option<String>,
}
