# Stored SHA selection and bounded baseline history

The Core history reader could select the earlier stored SHA when two modes
recorded the same scope and phase in the same second. Its aggregate query had
no tie-breaker. It also capped row count without bounding retained text, so a
small number of large metadata fields could still produce a large allocation.

Three before-fix Rust tests reproduce the two faults. The reader now selects
the greatest recorded timestamp, then the last stored row within that timestamp.
This is a storage-order tie-breaker. It does not establish finer scan-completion
time, Git ancestry, source coverage or a finding fix. Complete SHAs and run IDs
remain in the existing response. No schema or public tool option changes.

Both latest and full history reads retain the 10,000-row cap and now enforce an
8 MiB aggregate text cap. Borrowed SQLite text/blob byte lengths are checked
before copying fields into Rust strings. UTF-8 is counted in bytes. Exceeding
either cap returns an error rather than a truncated success or empty history.
This bounds retained field text, not SQLite's total allocation, query work,
database size, lock latency or downstream JSON/rendering memory.

The three coverage tools keep their Operate classification and cannot accept
Map or claim a fixed finding. The existing source-comparison request/byte
allowance and cancellation paths remain intact. Read failure never edits the
ledger. Recovery in the controlled fixture explicitly restores its saved small
history; product reads do not archive or remove rows automatically.

## Verification

- All 34 coverage-ledger checks and ten prepared-dispatch checks pass. The six
  directly changed behavior checks are rerun after test-helper cleanup. Cases
  include equal timestamps, reopening, older imports, UTF-8 byte accounting,
  oversized individual rows, real two-SHA consumer agreement, cancellation and
  transactional skip rollback.
- Three current registry/audit consistency contracts pass after updating the
  resource, artifact-consumption and recovery evidence for the coverage tools.
- Locked workspace build, Core all-target Clippy with warnings denied and the
  changed-code risk gate pass. Final repository summary evidence is recorded in
  the ignored draft receipt and is not a signed clean-commit receipt.
- Final J358 has 17 machine passes, zero failures, nineteen capture pairs and
  three formal operator judgments. Fourteen captured terminal-cell replays are
  reviewed across six sizes, refusal, explicit recovery, Setup and no-color
  restart. They are not OS screenshots or operator sign-off.
- J358 authenticates 6,561 repository inputs and thirteen frozen programs. The
  CLI SHA256 is
  `d5fd4e13c2807e3bda1f1516a5b9e19c0737dd0dab2ba2c0738cc12bdfb2f261`.
  Neither inputs nor programs change during the run.
- Two actual owned Git revisions and synthetic history rows survive unchanged.
  Listing and sweep select the same last stored SHA, including after restart.
  The oversized row remains present after refusal until explicit fixture
  restoration. No model request, scan job, target-source execution, observation,
  review decision, reservation or work attempt is created.

The first native attempt is retained with an incorrect Setup expectation under
the explicitly enabled onboarding-skip hook. The second completes the history
checks, but its short Setup wait can match command input. Final J358 waits for
the complete Setup heading and verifies that history reads have not accepted
Map. Production code and all thirteen executables are identical across the
native attempts. Initial test/risk/lint failures remain in the evidence root.

Evidence root: `scripts/devex/artifacts/baseline-history-20261024/`, including
before-fix failures, focused logs, frozen manifests, native receipts, captured
screens, the agent review and later-work preservation. The separate 34-file
publication index remains unchanged. This work remains unstaged on main.

The per-tool qualification and the original five open delivery items remain
open. General history throughput, query/lock bounds and complete reference-TUI
parity are not established by this controlled case.
