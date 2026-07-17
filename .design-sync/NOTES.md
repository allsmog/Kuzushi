# design-sync maintenance notes — Kuzushi current TUI

This project is deliberately self-contained under `.design-sync/`. The live TUI
is Rust/Ratatui and cannot be imported into Claude Design, so
`.design-sync/kit` is a small React projection of the current renderer contract.
It replaces the deleted `packages/kuzushi-tui-kit` path that made the previous
sync configuration non-buildable.

## Provenance

- Audited branch: `codex/atlas-native-cockpit`
- Audited HEAD: `ccb29faec323b52300b3f28e35bd85473ad841d7`
- Phase inventory: `app/view_state/sast_task_row.rs::ShellView`
- Primary dispatch: `renderer/render_app.rs`
- Phase composition: `renderer/views/workbench/`
- Bottom proposal card: `renderer/chrome/cards/render_plan_card.rs`
- Phase composer: `ui_view_models/prompt.rs` and
  `renderer/chrome/prompt/mod.rs`
- Run Focus: `renderer/views/activity/` and `ui_view_models/activity_*.rs`
- Setup: `renderer/views/onboarding/setup.rs` and
  `ui_view_models/setup/`
- Responsive goldens:
  `renderer/snapshots/phase_cockpit/phase_<phase>_<size>.snap`
- Route-family goldens: `tests/snapshots/*.snap`

Do not use `design/mockups/` or the old `ds-bundle/` as current truth. They
contain retired transcript/status-strip assumptions. The Rust sources and
committed renderer snapshots win whenever they disagree with this kit.

## Build

From the repository root:

```sh
npm --prefix .design-sync/kit ci
npm --prefix .design-sync/kit run build
```

The sync driver invocation is:

```sh
node .ds-sync/resync.mjs \
  --config .design-sync/config.json \
  --node-modules .design-sync/kit/node_modules \
  --entry .design-sync/kit/dist/index.js \
  --out /tmp/kuzushi-ds-bundle
```

The driver does not execute `buildCmd`; run the package build first. Keep the
generated bundle outside the repository so refreshing Claude Design does not
mutate `ds-bundle/` or any other Kuzushi artifact.

`dist/` and `node_modules/` are generated and ignored inside the nested kit.
The package lock is committed so a fresh checkout resolves the same React and
TypeScript toolchain.

## Preview contract

Package-shape preview discovery is strict: every top-level component needs an
authored `.design-sync/previews/<Component>.tsx`. Each PascalCase export in the
preview becomes a Claude Design example cell.

The previews must show current implementation states only. In particular:

- Five canonical phases are Map, Scan, Review, Prove, Fix.
- The phase prompt remains the last row.
- The returned `◆ PLAN` card is conditional and sits above that prompt.
- Planner-running state is Run Focus, not a permanent dock or transcript.
- `40×12`, `80×24`, `120×36`, and `160×48` examples exercise the real
  responsive cutovers.
- Example evidence, proof, artifacts, cost, and outcomes must be explicitly
  fixture data and internally consistent.

## Refresh checklist

1. Record branch and HEAD.
2. Compare `theme/mod.rs`, phase snapshots, prompt tokens, Plan card, Run Focus,
   Setup, attention, and route snapshots with the kit.
3. Update the kit and previews only where the renderer changed.
4. Build the nested package.
5. Run the design-sync driver and inspect every changed preview.
6. Confirm the git diff is confined to `.design-sync/**` unless the operator
   explicitly authorized a broader change.
