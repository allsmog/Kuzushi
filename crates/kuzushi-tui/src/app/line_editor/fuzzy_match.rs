//! Fuzzy matcher shim. The implementation now lives in
//! `kuzushi_core::text::fuzzy` so the tool catalog query and the shell share
//! one scorer; this re-export keeps the palette, completion, and file-picker
//! callers unchanged.
//!
//! Two forms: `subsequence_score` is permissive and belongs to surfaces the
//! operator is already reading (history search, finding search, value
//! ranking). `anchored_subsequence_score` additionally requires the needle to
//! start at a word boundary and belongs to command completion, where the
//! completed row is one Enter away from dispatch.

pub(crate) use kuzushi_core::text::fuzzy::{
    anchored_subsequence_score, rank_fuzzy, subsequence_score,
};
