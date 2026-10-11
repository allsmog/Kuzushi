# Setup source refresh, October 9, 2026

Explicitly reopening Setup now refreshes previously cached active-target facts
through the existing asynchronous, generation-checked inspector. This corrects
the stale branch/revision display observed during J148. The inspector clears
cached facts while loading; an already pending inspection is retained without
a duplicate probe. No model, discovery or phase-completion work is introduced.

Two focused tests exercise actual owned Git commits and an existing pending
generation. They verify revision replacement, retained selected Map tasks,
Setup cursor and multiline composer, with no active phase or tool run. Thirteen
existing Setup renderer tests also pass; their fixture now opens Setup before
waiting for resolved facts. Production renderer behavior is unchanged.

Evidence root: /tmp/kuzushi-setup-source-refresh-20261009.
Final J149: /tmp/kuzushi-setup-source-refresh-20261009/tui/20261009-161339/J149.
Native SHA-256:
9e15311fbcb18f3a93bb8db3a99ace296065e76827cf9ebb653aad4a6f55a597.

J149 records 19 machine passes, zero failures and 12 live text/ANSI pairs across
40x12, 60x20, 80x24, 96x89, 120x36 and 160x48, including no-color restart.
All captures match the native binary, requested/actual dimensions and plain text
after ANSI removal. Four scoped assistant screen judgments remain separate from
raw REVIEW_REQUIRED and operator approval false.

The owned inert fixture has two actual Git commits and a same-SHA working-tree
edit. Setup refreshes from the original main commit to a later fixture branch,
then shows dirty source without restart. Wide layouts expose those facts;
compact layouts intentionally omit the facts block while retaining readiness
controls and the composer draft. The observed short-input echo is ten ms on
this fixture, not a general latency or reference-parity result. No-color restart
retains current dirty facts and still requires genuine Map work. Fixture checks
verify expected source edits, unchanged isolated model configuration and zero
findings, decisions, provider reservations or investigation work attempts.

Fifteen distinct focused tests, the workspace build and the CRAP-risk proxy pass.
The proxy inspected 530 changed code files. All ten quick repository summary steps pass. The verifier records dirty source
and `driftedDuringRun: true`. Dirty source alone sets that flag, so it does not
prove a concurrent edit or certify a clean committed snapshot.
The receipt is recorded in the matrix checkpoint and evidence root; final
documentation checks run after this update. Work remains
uncommitted on main; no product commit, push, OAuth renewal or inference occurs.

This increment does not provide automatic invalidation while Setup stays open,
atomic source facts, a total inspection IO bound, or semantic scroll anchoring.
The inspector also performs existing inventory, profile, file-count and SBOM
work; it is not a constant-time Git-only refresh. Only the stated selection and
editor states are qualified. Completed inspection with no detected languages
still renders "languages: detecting" on this text-only fixture. Operational
error diagnostics and premature journey/autonomy chrome on Logs and Quit remain
open from J148. Complete TUI acceptance and live investigation validation remain
open. Tool qualification stays 55 of 109, with 54 unassigned.
