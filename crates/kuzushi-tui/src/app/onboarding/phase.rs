//! Compatibility shim: `WorkflowPhase` now lives in `kuzushi-core` so the
//! shared tool-dispatch boundary and the autonomy gate can reason about the
//! 組→崩→作→掛 engagement spine without depending on the TUI crate. The enum
//! and all of its pure methods (`ORDER`, `next`/`previous`, `parse`,
//! `label`/`kanji`/`word`/`intent`/`position`) are unchanged — they moved
//! verbatim into `kuzushi_core::modules::autonomy::workflow_phase`. This
//! re-export keeps every `crate::app::onboarding::phase::WorkflowPhase` and
//! `crate::app::WorkflowPhase` import site working untouched.

pub use kuzushi_core::WorkflowPhase;
