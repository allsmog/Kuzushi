# Rust Migration Status

This file is historical. It used to track TypeScript-to-Rust parity row by row
during the Rust cutover. The live built-in runtime is now Rust-native, and old
rows in the migration ledger had become a misleading architecture contract.

For current guidance, use:

- `AGENTS.md` for agent-facing editing rules and mode parity.
- `docs/modules.md` for the retained module/SDK contract.
- `docs/assessments/mode-parity.md` for current scan/shell/run parity.
- `docs/architecture/domain-boundaries.md` for Rust ownership boundaries.

Do not add new current-status rows here. If a migration-specific historical
note is needed, put it under `docs/notes/` and label it explicitly as
historical.
