# Juice Shop 20-scan adversarial campaign

This directory is the human-readable source of truth for the threat seasoning used by the isolated Juice Shop campaign.

The campaign deliberately creates **exactly twenty independent model scans**:

- four source shards: authentication, server/API, data/models, and frontend/client trust;
- five adversarial threat lenses from `juice-shop-adversary-model.json`;
- one explicitly pinned model per cell.

That produces a `4 × 5 × 1` matrix. Each cell receives a separate model invocation, separate scope file, separate seasoned prompt, separate run receipt, and separate budget backstop. The matrix is not twenty copies of one vague prompt: each pass has a distinct trust-boundary hypothesis while retaining the instruction to preserve valid off-focus findings.

## Evidence and proof policy

The threat model changes search order; it does not lower the bar for accepting findings. Model output remains a candidate signal. The pipeline subsequently performs:

1. deterministic CPG, secret, Semgrep, and taint analysis;
2. isolated Schemathesis, ZAP, and custom HTTP mutation against a local container;
3. corpus deduplication;
4. three-vote, code-reading triage across the combined ledger;
5. attack-chain synthesis over surviving findings;
6. adversarial model verification and bounded empirical verification for prioritized findings;
7. final JSONL, SARIF, Markdown, provenance, and checksum exports.

No public target is contacted. No patch is generated or applied. Intentional Juice Shop challenge behavior is not automatically treated as a false positive: the campaign looks for unintended boundary escape, new reachability, cross-challenge composition, and regressions at the exact PR commit.
