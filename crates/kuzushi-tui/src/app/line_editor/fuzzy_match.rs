//! Fuzzy matcher shim. The implementation now lives in
//! `kuzushi_core::text::fuzzy` so the tool catalog query and the shell share
//! one scorer; this re-export keeps the palette, completion, and file-picker
//! callers unchanged.

pub(crate) use kuzushi_core::text::fuzzy::{rank_fuzzy, subsequence_score};
