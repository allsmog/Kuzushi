## Kuzushi TUI Kit — conventions

This library renders the **Kuzushi terminal (Ratatui) shell** look: a dark,
monospace "growing console" of timestamped log lines, findings, and a status
strip. Build security-tool and terminal-style UIs by **composing its
components** — never hand-write terminal markup or invent class names.

### Wrap everything in `TermFrame`

Every screen is a `TermFrame` — the dark, rounded terminal window. It supplies
the background, the monospace grid, and (optionally) the macOS traffic-light
chrome. **A primitive placed outside a `TermFrame` renders as light text on
nothing** — always nest `StatusStrip`, `Row`, `SectionHeader`, `LogLine`,
`Footer`, `SeverityBadge`, and `Glyph` inside one.

- `cols={N}` fixes the grid to N monospace columns (the real shell runs 120;
  a full status strip needs ~100). Omit `cols` to fill the container.
- `chromeless` drops the traffic-light bar for an embedded panel.

Import the stylesheet once at your app root — there is **no theme provider**,
all styling ships in this sheet:

```tsx
import "@kuzushi/tui-kit/styles.css";
```

### Color is a `tone`, never a class or hex

Don't write CSS classes or color literals. Every text-bearing component takes a
semantic `tone` from the 8-role theme plus the severity scale:

`primary` · `muted` · `subtle` · `accent` · `label` · `heading` · `success` ·
`warn` · `danger` · `selection` · `critical` · `high` · `medium` · `low`

- `Glyph tone="…"` colors any text run or status glyph (`✓ ✗ ● ▸ ◆ … ⏵ ·`).
- `Row tone="…"` colors a whole line; `Row selected` paints the j/k cursor
  highlight (inverse accent), and `Row cols={N}` extends it full-width.
- `LogLine kind="…"` picks the leading glyph and tone for you. Kinds:
  `in` · `run` · `ok` · `err` · `agent` · `flow` · `find` · `log`.
- `SeverityBadge level="…"` — `critical` · `high` · `medium` · `low`.

One inherited rule: `accent` (#7fb8ff) is reserved for next-action callouts and
selection — never decoration.

### Where the truth lives

- `styles.css` (and the sheet it imports) defines the palette as `--kz-*`
  custom properties and the `kz-*` classes — read it before restyling.
- Each component ships a `<Name>.prompt.md` (usage) and `<Name>.d.ts` (the prop
  contract). The eight components: `TermFrame`, `StatusStrip`, `Row`, `Glyph`,
  `SectionHeader`, `LogLine`, `Footer`, `SeverityBadge`.

### Idiomatic example

```tsx
<TermFrame title="kuzushi · sast" cols={100}>
  <StatusStrip target="~/work/acme-checkout" module="sast" cost="$0.41" cols={100} />
  <Row> </Row>
  <SectionHeader label="FINDINGS · 2 critical" cols={100} />
  <LogLine kind="find" time="14:33:42">
    {" "}<Glyph tone="primary">F-0012</Glyph>{" · "}
    <SeverityBadge level="critical" />{" · refund-bot.ts:127"}
  </LogLine>
  <Footer
    stage="sast:scan"
    findings={11}
    module="sast"
    keybinds={[{ key: "/findings", hint: "browse" }, { key: "/open", hint: "F-0001" }]}
    cols={100}
  />
</TermFrame>
```
