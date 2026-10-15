# Terminal Escape prefixes

October 10, 2026. J182 confirmed that batched Escape/End inserted `[4~` into the
composer. The pinned crossterm 0.29.0 Unix parser consumed two Escape prefixes
as one event, then decoded the remaining End bytes as literal characters.
Direct parser tests reproduced the corruption and lost repeated Escape presses.

## Change and maintenance

The workspace uses a narrowly patched, version-pinned copy of crossterm 0.29.0.
Only the two Unix input backends change production behavior. When a second
Escape arrives after a pending standalone Escape, the parser publishes the first
Escape and retains the new prefix for the next key. Bracketed paste buffers do
not take that path. No sequence-looking characters are stripped from typed or
pasted content. No keyboard reporting mode or terminal preference is changed.

The original crates.io archive and MIT license remain in the repository. Its
checksum matches the prior registry lockfile. All untouched package files are
checked against the authenticated archive. New and modified local functions
receive the normal risk, complexity and size limits; identical upstream
functions are the copied-code baseline. Tests reject archive substitution,
unexpected upstream edits, a branchy local addition and excessive local file
size. [Maintenance instructions](../../third-party/README.md) describe the
override and its removal conditions. Workspace dependency versions are unchanged.

An enhanced-keyboard probe did not establish support in the tested tmux pane.
Enabling that protocol alone could not qualify a fix there. The dependency
repair preserves the existing input and rendering architecture.

## Verification

The dependency's default library suite passes 98 tests, including five local
parser regressions; seven upstream tests remain ignored. The alternate Unix
backend passes those five regressions too. Coverage includes every input split
for Escape/navigation, repeated Escape, split Unicode, encoded modifiers,
ordinary Alt characters and literal escape pairs inside bracketed paste.

128 focused Kuzushi terminal tests pass, with the separate performance test
ignored. The initial run exposed a stale first-Map fixture: it simulated active
Map execution while retaining Setup ownership. The fixture now explicitly
establishes committed-plan ownership and also checks that the chip was hidden
before it. No phase inference or display policy changed to satisfy the test.
Fifteen Node quality contracts, workspace build and the 100-file changed-code
risk gate pass. That file count includes authenticated copied dependency files.
All ten repository summary gates pass. The first summary failure and its
receipt are preserved; two test-template lint warnings were corrected before
the passing run. The final unsigned receipt is
`/tmp/kuzushi-terminal-keyboard-20261010/precommit-verify-receipt.json`.
It records dirty/drifted state and cannot attest to a clean commit. A separate
index check confirms all 74 untouched staged package files match the original
archive byte for byte, including preserved upstream line endings.
CI declares the dependency suites in the main Rust job and the macOS terminal
job; their remote execution remains unverified until an approved publication.

Final J183 is at
`/tmp/kuzushi-terminal-keyboard-20261010/final-native/20261010-194855/J183`.
It records 34 machine passes, zero failures and 25 authenticated live text/ANSI
captures. Native SHA-256 is
`61c0d0d058fcb5561252199d6427d89f442100543431b193af8c7e88caeb6b79`.
All six required sizes retain the paste and appended draft. At 40×12, the
inspector shows all original lines and its controls. Literal `[4~` remains when
typed or pasted, while batched Escape/End no longer introduces it. Two Escape
presses clear the draft then enter Navigate mode. Typed quit and no-color
restart also complete. Post-exit inspection confirms unchanged owned source,
zero run results, zero provider requests and no target source execution.

The earlier run under
`/tmp/kuzushi-terminal-keyboard-20261010/native/20261010-194738/J183` remains
preserved. Its paste-clear expectation failed because the visible notice owned
the first Escape. The final journey dismisses that notice before inspection;
it does not weaken the draft-clear assertion. Journey files and helpers were
not edited while their processes were live.

Scoped assistant screen judgments remain separate from raw REVIEW_REQUIRED and
operator approval false. This input repair does not establish complete workflow
acceptance or reference parity.

## Limits

Legacy double-Escape navigation is also an ambiguous encoding of Alt plus that
navigation key. The patch interprets it as Escape followed by navigation;
ordinary Alt characters and explicit encoded modifiers retain their semantics.
Native evidence covers macOS with tmux. The alternate Unix backend has parser
test evidence, while Windows input remains unchanged. Cross-platform terminal
acceptance, broad input latency and the full investigation journey remain open.
