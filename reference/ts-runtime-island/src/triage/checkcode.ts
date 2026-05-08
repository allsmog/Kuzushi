/**
 * CheckCode — vulnerability assessment verdict spectrum, lifted from
 * lib/msf/core/exploit.rb (Msf::Exploit::CheckCode).
 *
 * A unified contract for any tool that determines whether a target/finding
 * is vulnerable. Replaces ad-hoc booleans/strings with a six-state spectrum:
 *
 *   unsupported < unknown < safe < detected < appears < vulnerable
 *
 * Mapping into Kuzushi's existing Verdict ('tp' | 'fp' | 'needs_review' |
 * 'by_design'):
 *
 *   vulnerable   → tp
 *   appears      → needs_review (high lean toward tp)
 *   detected     → needs_review
 *   safe         → fp
 *   by-design    → by_design
 *   unknown      → needs_review
 *   unsupported  → needs_review (no triage capability)
 */

import type { Verdict } from "../types.js";

export type CheckCodeKind =
  | "unknown"
  | "safe"
  | "detected"
  | "appears"
  | "vulnerable"
  | "unsupported";

export interface CheckCode {
  kind: CheckCodeKind;
  /** Short human reason ("HTTP 500", "version 1.2.3 not vulnerable", etc.). */
  reason?: string;
  /** Free-form structured details (HTTP body excerpt, banner, version, etc.). */
  details?: Record<string, unknown>;
  /**
   * For `vulnerable` only — vulnerability metadata to surface in reporting.
   * (CVE, CWE, CVSS, etc.)
   */
  vuln?: Record<string, unknown>;
}

/** Factory helpers — mirrors Msf::CheckCode::Foo. */
export const Check = {
  unknown(reason?: string, details?: Record<string, unknown>): CheckCode {
    return {
      kind: "unknown",
      ...(reason !== undefined ? { reason } : {}),
      ...(details !== undefined ? { details } : {}),
    };
  },
  safe(reason?: string, details?: Record<string, unknown>): CheckCode {
    return {
      kind: "safe",
      ...(reason !== undefined ? { reason } : {}),
      ...(details !== undefined ? { details } : {}),
    };
  },
  detected(reason?: string, details?: Record<string, unknown>): CheckCode {
    return {
      kind: "detected",
      ...(reason !== undefined ? { reason } : {}),
      ...(details !== undefined ? { details } : {}),
    };
  },
  appears(reason?: string, details?: Record<string, unknown>): CheckCode {
    return {
      kind: "appears",
      ...(reason !== undefined ? { reason } : {}),
      ...(details !== undefined ? { details } : {}),
    };
  },
  vulnerable(
    reason?: string,
    details?: Record<string, unknown>,
    vuln?: Record<string, unknown>,
  ): CheckCode {
    return {
      kind: "vulnerable",
      ...(reason !== undefined ? { reason } : {}),
      ...(details !== undefined ? { details } : {}),
      ...(vuln !== undefined ? { vuln } : {}),
    };
  },
  unsupported(reason?: string): CheckCode {
    return { kind: "unsupported", ...(reason !== undefined ? { reason } : {}) };
  },
};

/** Order — higher = stronger evidence of vulnerability. */
export const CHECK_RANK: Record<CheckCodeKind, number> = {
  unsupported: 0,
  unknown: 1,
  safe: 2,
  detected: 3,
  appears: 4,
  vulnerable: 5,
};

/** Project a CheckCode onto the legacy Verdict enum used by the triage store. */
export function checkCodeToVerdict(code: CheckCode): Verdict {
  switch (code.kind) {
    case "vulnerable":
      return "tp";
    case "safe":
      return "fp";
    case "appears":
    case "detected":
    case "unknown":
    case "unsupported":
    default:
      return "needs_review";
  }
}

/** Pretty-print a CheckCode for shell output. */
export function formatCheckCode(code: CheckCode): string {
  const tag = code.kind.toUpperCase();
  return code.reason ? `${tag}: ${code.reason}` : tag;
}

/** Pick the strongest CheckCode from a list (e.g. multiple checkers running). */
export function maxCheckCode(codes: ReadonlyArray<CheckCode>): CheckCode | undefined {
  if (codes.length === 0) return undefined;
  return [...codes].sort((a, b) => CHECK_RANK[b.kind] - CHECK_RANK[a.kind])[0];
}
