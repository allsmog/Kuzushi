pub(in crate::renderer) use super::*;

mod siblings;
pub(crate) use siblings::*;
mod current_threat_model_doc;
/// Returns the canonical 6-row STRIDE rollup matching the design fixture.
/// Used as a fallback when no `.kuzushi/threat-model.json` is present.

/// Canonical 10-row ASCII DFD matching `design/mockups/threat-model.jsx`.
/// 5 boxed nodes + 2 annotated edges (jwt, plaintext PII).

/// Extract `(id, node_type, trust_zone)` triples from `dfd.nodes` if present.

/// Try to load the persisted threat model for the active workspace target.
/// Returns `None` if the file doesn't exist or is empty/null.

/// Compute the STRIDE rollup from a persisted threat model document.
/// Returns `None` if the document has no `threats` array or it's empty.
mod items_1;
mod items_2;
mod stride_rollup_from_doc;
pub(crate) use current_threat_model_doc::current_threat_model_doc;
pub(crate) use items_1::stride_rollup_rows;
pub(crate) use items_1::stride_row;
pub(crate) use items_1::threat_nav;
pub(crate) use items_2::dfd_canonical_lines;
pub(crate) use items_2::dfd_nodes_from_doc;
pub(crate) use stride_rollup_from_doc::stride_rollup_from_doc;
