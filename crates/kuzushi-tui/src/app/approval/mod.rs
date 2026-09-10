use super::*;
pub(crate) use super::*;

/// Stable key for a `<tool> <target>` allowlist/denylist entry.

/// Returns a `PendingConfirm` when `<tool>` + `<input>` look like a
/// gated dispatch per `design/mockups/confirm-dialog.jsx`:
///
///   - `sandbox:run` (or any `*:run` tool) with a `target` URL or
///     `network: true` → CONFIRM · network egress
///   - `fs:write` with a `path` outside `.kuzushi/` →
///     CONFIRM · fs:write outside .kuzushi/
///   - any tool whose `cmd` / `verb` matches a destructive pattern
///     (`rm -rf`, `git push --force`, `:force`, `chmod -R 777`,
///     `> /dev/`, ...) → REFUSED · destructive verb (no override).
///
/// `allowlist` is consulted first — already-approved `<tool> <target>`
/// entries skip the gate entirely.  Returns None for tools that aren't
/// known-risky.

/// Pattern-match destructive shell verbs.  Conservative: only flags
/// patterns that are unambiguously destructive (no false-positives on
/// `git push origin foo` etc.).

/// Project the typed, persisted `PatchResult` returned by `patch:finding`
/// into the shell review gate. Legacy ad-hoc patch-shaped JSON is not
/// apply-authoritative.
pub(crate) use confirm_gate_for_tool::*;
pub(crate) use contains_destructive_shell_fragment::*;
pub(crate) use label::*;
pub(crate) use selected_patch::*;
pub(crate) mod allowance;
mod confirm_gate_for_tool;
mod contains_destructive_shell_fragment;
mod label;
mod selected_patch;
pub use confirm_gate_for_tool::confirm_gate_for_tool;
pub use contains_destructive_shell_fragment::parse_pending_patch;
pub use label::ConfirmKind;
pub use label::PendingConfirm;
pub use label::PendingPatch;
