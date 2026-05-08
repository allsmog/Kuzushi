pub(crate) use super::prelude::*;
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

/// Parse a `patch:run` / `patch:finding` result into a `PendingPatch`.
/// Tools should produce `data` shaped like:
///   `{ alias, rationale, side_effect?, diff, tests: [{name, blurb}],
///      guardrail?, staged_at? }`
/// All fields except `alias` + `rationale` + `diff` are optional —
/// missing fields collapse to None / empty.
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
pub use items_1::ConfirmKind;
pub use items_1::PendingConfirm;
pub use items_1::PendingPatch;
pub use items_2::confirm_gate_for_tool;
pub use items_3::parse_pending_patch;
