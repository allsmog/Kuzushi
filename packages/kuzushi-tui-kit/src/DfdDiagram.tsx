import { Fragment } from "react";
import { Glyph } from "./Glyph";
import { Row } from "./Row";
import type { Tone } from "./tokens";

/** A node's role in the data-flow diagram. */
export type NodeKind = "entity" | "process" | "store";

export interface DfdNode {
  /** Node label (e.g. `Browser`, `Order Service`, `Postgres`). */
  label: string;
  /** entity ◆ · process ◇ · store ▣ — sets the glyph and tone. */
  kind: NodeKind;
}

export interface TrustZone {
  /** Zone / trust-boundary name (e.g. `Internet`, `App VPC`, `Data`). */
  name: string;
  /** The nodes inside this zone. */
  nodes: DfdNode[];
  /** The flow leaving this zone toward the next (label + whether it crosses a boundary). */
  flowToNext?: { label: string; boundary?: boolean };
}

const NODE: Record<NodeKind, { glyph: string; tone: Tone }> = {
  entity: { glyph: "◆", tone: "label" },
  process: { glyph: "◇", tone: "accent" },
  store: { glyph: "▣", tone: "high" },
};

export interface DfdDiagramProps {
  /** The trust zones, top to bottom along the data flow. */
  zones: TrustZone[];
}

/**
 * The data-flow diagram — stacked trust-zone panels holding node boxes
 * (`◆` external entity / `◇` process / `▣` data store) connected by flows, with
 * trust-boundary crossings marked in amber `▶`, mirroring the Rust threat-model
 * DFD. It shows how data moves across trust boundaries — every amber crossing is
 * a place to check authn/authz and validation. A legend counts nodes, flows,
 * and boundary crossings.
 *
 * @example
 * <DfdDiagram zones={[
 *   { name: "Internet", nodes: [{ label: "Browser", kind: "entity" }],
 *     flowToNext: { label: "HTTPS", boundary: true } },
 *   { name: "App VPC", nodes: [
 *       { label: "API Gateway", kind: "process" },
 *       { label: "Order Service", kind: "process" }],
 *     flowToNext: { label: "SQL", boundary: true } },
 *   { name: "Data", nodes: [{ label: "Postgres", kind: "store" }] },
 * ]} />
 */
export function DfdDiagram({ zones }: DfdDiagramProps) {
  const inner = Math.max(
    24,
    ...zones.map((z) => z.name.length + 4),
    ...zones.flatMap((z) => z.nodes.map((n) => n.label.length + 4)),
  );
  const nodeCount = zones.reduce((n, z) => n + z.nodes.length, 0);
  const flows = zones.filter((z) => z.flowToNext).length;
  const crossings = zones.filter((z) => z.flowToNext?.boundary).length;
  return (
    <>
      {zones.map((z, zi) => {
        const head = `╭─ ${z.name} `;
        const fill = "─".repeat(Math.max(0, inner - (z.name.length + 3)));
        return (
          <Fragment key={zi}>
            <Row>
              {" "}
              <Glyph tone="subtle">{`${head}${fill}╮`}</Glyph>
            </Row>
            {z.nodes.map((n, ni) => {
              const node = NODE[n.kind];
              const pad = " ".repeat(Math.max(1, inner - (n.label.length + 3)));
              return (
                <Row key={ni}>
                  {" "}
                  <Glyph tone="subtle">│ </Glyph>
                  <Glyph tone={node.tone}>{`${node.glyph} ${n.label}`}</Glyph>
                  <Glyph tone="subtle">{`${pad}│`}</Glyph>
                </Row>
              );
            })}
            <Row>
              {" "}
              <Glyph tone="subtle">{`╰${"─".repeat(inner)}╯`}</Glyph>
            </Row>
            {z.flowToNext ? (
              <Row>
                {"      "}
                <Glyph tone="subtle">│ </Glyph>
                <Glyph tone={z.flowToNext.boundary ? "warn" : "subtle"}>▶</Glyph>
                <Glyph tone="muted">{` ${z.flowToNext.label}`}</Glyph>
                {z.flowToNext.boundary ? <Glyph tone="warn">{"  (trust boundary)"}</Glyph> : null}
              </Row>
            ) : null}
          </Fragment>
        );
      })}
      <Row> </Row>
      <Row>
        {" "}
        <Glyph tone="muted">{`${nodeCount} nodes · ${flows} flows · ${crossings} boundary crossings`}</Glyph>
      </Row>
      <Row>
        {" "}
        <Glyph tone="subtle">amber </Glyph>
        <Glyph tone="warn">▶</Glyph>
        <Glyph tone="subtle"> = trust-boundary crossing · grey = in-zone</Glyph>
      </Row>
    </>
  );
}
