pub(in crate::renderer) use super::*;

pub(in crate::renderer) use current_threat_model_doc::*;
pub(in crate::renderer) use dfd_canonical_lines::*;
pub(in crate::renderer) use stride_rollup_from_doc::*;
pub(in crate::renderer) use threat_nav::*;
mod current_threat_model_doc;
mod dfd_canonical_lines;
mod stride_rollup_from_doc;
/// Returns the canonical 6-row STRIDE rollup matching the design fixture.
/// Used as a fallback when no `.kuzushi/threat-model.json` is present.

/// Canonical 10-row ASCII DFD matching `design/mockups/threat-model.jsx`.
/// 5 boxed nodes + 2 annotated edges (jwt, plaintext PII).

/// Extract `(id, node_type, trust_zone)` triples from `dfd.nodes` if present.

/// Try to load the persisted threat model for the active workspace target.
/// Returns `None` if the file doesn't exist or is empty/null.

/// Compute the STRIDE rollup from a persisted threat model document.
/// Returns `None` if the document has no `threats` array or it's empty.
mod threat_nav;
pub(crate) use current_threat_model_doc::current_threat_model_doc;
pub(crate) use dfd_canonical_lines::dfd_canonical_lines;
pub(crate) use dfd_canonical_lines::dfd_nodes_from_doc;
pub(crate) use stride_rollup_from_doc::stride_rollup_from_doc;
pub(crate) use threat_nav::stride_rollup_rows;
pub(crate) use threat_nav::stride_row;
pub(crate) use threat_nav::threat_nav;
