import { Fragment } from "react";
import { Glyph } from "./Glyph";
import { Row } from "./Row";
import type { Severity, Tone } from "./tokens";

const SEV_TONE: Record<Severity, Tone> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  unknown: "unknown",
};

export interface AttackChain {
  /** Chain label (e.g. `SQLi in /search → dump users`). */
  label: string;
  /** Chain severity — tones the branch. */
  severity: Severity;
  /** Optional preconditions/steps, shown as indented leaves. */
  steps?: string[];
}

export interface AttackTreeProps {
  /** The attacker's goal (root box). */
  goal: string;
  /** The impact if the goal is reached (e.g. `account takeover`). */
  impact?: string;
  /** `OR` — any one chain suffices (◇ accent); `AND` — all required (◆ warn). */
  gate?: "OR" | "AND";
  /** The candidate chains toward the goal. */
  chains: AttackChain[];
  /** Count of further chains not shown (renders a `+N more chains` leaf). */
  moreChains?: number;
}

/**
 * The exploit attack tree — a `☠` attacker-goal root over an `◇ OR` (any one
 * chain, accent) or `◆ AND` (all required, warn) gate, with severity-toned
 * chain branches and their precondition steps, mirroring the Rust scene attack
 * tree. It answers "how could this be reached, and by which of several paths?"
 * — the reddest branch is the cheapest exploit. Overflow collapses to a
 * `+N more chains` leaf.
 *
 * @example
 * <AttackTree goal="steal customer PII" impact="account takeover" gate="OR" chains={[
 *   { label: "SQLi in /search → dump users", severity: "high",
 *     steps: ["unauthenticated endpoint", "error-based extraction"] },
 *   { label: "IDOR on /invoice → cross-tenant read", severity: "medium" },
 * ]} moreChains={2} />
 */
export function AttackTree({ goal, impact, gate = "OR", chains, moreChains }: AttackTreeProps) {
  const gateGlyph = gate === "OR" ? "◇" : "◆";
  const gateTone: Tone = gate === "OR" ? "accent" : "warn";
  const gateHint = gate === "OR" ? "any one chain" : "all steps required";
  const lastChain = chains.length - 1;
  return (
    <>
      <Row>
        {" "}
        <Glyph tone="critical">{`☠ ${goal}`}</Glyph>
        {impact ? <Glyph tone="muted">{` — ${impact}`}</Glyph> : null}
      </Row>
      <Row>
        {" "}
        <Glyph tone="subtle">│</Glyph>
      </Row>
      <Row>
        {" "}
        <Glyph tone={gateTone}>{`${gateGlyph} ${gate}`}</Glyph>
        <Glyph tone="muted">{` — ${gateHint}`}</Glyph>
      </Row>
      {chains.map((c, i) => {
        const isLast = i === lastChain && moreChains == null;
        const branch = isLast ? "╰─" : "├─";
        return (
          <Fragment key={i}>
            <Row>
              {" "}
              <Glyph tone="subtle">{branch} </Glyph>
              <Glyph tone={SEV_TONE[c.severity]}>{c.severity.toUpperCase()}</Glyph>
              <Glyph tone="primary">{`  ${c.label}`}</Glyph>
            </Row>
            {(c.steps ?? []).map((step, j) => {
              const spine = isLast ? "   " : "│  ";
              const leaf = j === (c.steps as string[]).length - 1 ? "╰" : "├";
              return (
                <Row key={j}>
                  {" "}
                  <Glyph tone="subtle">{`${spine} ${leaf} `}</Glyph>
                  <Glyph tone="muted">{step}</Glyph>
                </Row>
              );
            })}
          </Fragment>
        );
      })}
      {moreChains != null ? (
        <Row>
          {" "}
          <Glyph tone="subtle">╰─ </Glyph>
          <Glyph tone="muted">{`+${moreChains} more chains`}</Glyph>
        </Row>
      ) : null}
    </>
  );
}
