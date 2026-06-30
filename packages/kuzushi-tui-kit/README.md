# @kuzushi/tui-kit

A small React component kit that reproduces the **Kuzushi terminal (Ratatui)
shell** design language for the web — so Claude Design (claude.ai/design) can
build TUI-style screens out of the project's *real* primitives.

The live shell is a native Rust application
(`crates/kuzushi-tui`); it cannot be rendered on the web directly. This kit is
the faithful web counterpart: its tokens (the 8-role color theme, severity
scale, JetBrains Mono grid) mirror `crates/kuzushi-tui/src/theme/mod.rs`
one-to-one, and its components are the same growing-console primitives every
screen is composed from in `design/mockups/_shared.jsx`.

## Use

```tsx
import "@kuzushi/tui-kit/styles.css";
import { TermFrame, StatusStrip, SectionHeader, LogLine, SeverityBadge, Footer } from "@kuzushi/tui-kit";

<TermFrame title="kuzushi · sast" cols={96}>
  <StatusStrip target="~/work/acme-checkout" module="sast" cost="$0.41" />
  <Row> </Row>
  <SectionHeader label="FINDINGS · 2 critical" cols={96} />
  <LogLine kind="find" time="14:33:42">
    {" "}<Glyph tone="primary">F-0012</Glyph> · <SeverityBadge level="critical" /> · refund-bot.ts:127
  </LogLine>
  <Footer stage="sast:scan" findings={11} module="sast"
    keybinds={[{ key: "/findings", hint: "browse" }, { key: "/open", hint: "F-0001" }]} />
</TermFrame>
```

## Components

| Component | What it is |
|---|---|
| `TermFrame` | The terminal window (chrome + monospace body) every screen lives in. |
| `StatusStrip` | The always-visible top line: target / ctx / model / module / cost. |
| `Row` | One line of the terminal grid; the unit the console grows by. |
| `Glyph` | A run of text or a status glyph in one semantic `tone`. |
| `SectionHeader` | A `── LABEL ──────` divider grouping console output. |
| `LogLine` | A console line: timestamp + kind glyph + message. |
| `Footer` | Rule + stage/findings status + keybind contract + prompt. |
| `SeverityBadge` | A `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` severity chip. |

All color comes from the `tone` vocabulary in `src/tokens.ts`; the class names
it maps to live in `src/styles.css`.

## Build

```bash
npm install
npm run build   # → dist/ (ESM + .d.ts + styles.css)
```

This package is intentionally isolated from the Kuzushi CLI: it is not a member
of the repo's pnpm workspace and carries its own `node_modules`, so React never
enters the CLI build.
