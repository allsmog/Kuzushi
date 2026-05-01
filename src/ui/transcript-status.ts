/**
 * msfconsole-style status line vocabulary.
 *
 *   [*] info / advisory          — neutral framing line
 *   [+] success / created        — something good happened
 *   [-] failure / error          — something bad happened
 *   [!] warning / attention      — operator should look
 *
 * Used by the shell + dispatcher to frame their output the way an analyst
 * sitting in front of msfconsole would expect. Orthogonal to the per-actor
 * Claude-Code transcript glyphs (`⏺ / ● / ⎿ / ✻ / ★`) emitted from inside
 * a module run — both can appear in the same scrollback.
 *
 * The helpers here intentionally return raw strings rather than React
 * elements: they're consumed identically by Ink, the plain-renderer and
 * the CI stream, so the cost of a shared formatter is one indirection
 * and the win is single-source vocabulary across all three sinks.
 */

import { tokens } from "./tokens.js";

export type StatusLineKind = "info" | "ok" | "fail" | "warn";

interface StatusGlyph {
  readonly raw: string;
  readonly color: (text: string) => string;
}

const GLYPHS: Record<StatusLineKind, StatusGlyph> = {
  info: { raw: "[*]", color: tokens.info },
  ok: { raw: "[+]", color: tokens.success },
  fail: { raw: "[-]", color: tokens.danger },
  warn: { raw: "[!]", color: tokens.warn },
};

/**
 * Render a status line with ANSI coloring on the leading glyph. The body
 * is not recolored so callers can layer their own emphasis (e.g. tokens.strong
 * on a module id) without fighting a wrapper style.
 */
export function formatStatusLine(kind: StatusLineKind, message: string): string {
  const glyph = GLYPHS[kind];
  return `${glyph.color(glyph.raw)} ${message}`;
}

/** Plain (un-colored) form, for plain-renderer / CI sinks. */
export function plainStatusLine(kind: StatusLineKind, message: string): string {
  return `${GLYPHS[kind].raw} ${message}`;
}

/**
 * Strip a leading `[*]/[+]/[-]/[!]` prefix from a string so callers can
 * detect a status-line and re-emit it via the canonical formatter without
 * double-bracketing. Returns `null` when no prefix matches.
 */
export function parseStatusLine(line: string): { kind: StatusLineKind; message: string } | null {
  const match = /^(\[[*+\-!]\])\s*(.*)$/.exec(line);
  if (!match) return null;
  const [, prefix, body] = match;
  switch (prefix) {
    case "[*]":
      return { kind: "info", message: body ?? "" };
    case "[+]":
      return { kind: "ok", message: body ?? "" };
    case "[-]":
      return { kind: "fail", message: body ?? "" };
    case "[!]":
      return { kind: "warn", message: body ?? "" };
    default:
      return null;
  }
}
