/**
 * Unit tests for the transcript formatter helpers.
 *
 * Covers each `AgentActivityLine.kind`, the truncation path, the
 * fingerprint label parser, and the deterministic actor short id.
 */
import { describe, expect, it } from "vitest";
import { BLACK_CIRCLE, FINDING_GLYPH, LOWER_HOOK, THINKING_GLYPH } from "../../src/ui/glyphs.js";
import type { AgentActivityLine } from "../../src/ui/state.js";
import {
  actorLabelFromFingerprint,
  actorShortId,
  toCompactRow,
  toTranscriptEntry,
} from "../../src/ui/transcript-format.js";

function line(partial: Partial<AgentActivityLine>): AgentActivityLine {
  return {
    kind: "tool-start",
    index: 0,
    total: 1,
    ...partial,
  };
}

describe("toCompactRow", () => {
  it("renders tool-start as → with target detail", () => {
    const row = toCompactRow(line({ kind: "tool-start", toolName: "Read", detail: "src/foo.ts" }));
    expect(row.glyph).toBe("→");
    expect(row.action).toBe("Read");
    expect(row.target).toBe("src/foo.ts");
  });

  it("renders tool-complete as ✓ with summary detail", () => {
    const row = toCompactRow(
      line({ kind: "tool-complete", toolName: "Read", detail: "138 lines, 4.2KB" }),
    );
    expect(row.glyph).toBe("✓");
    expect(row.summary).toBe("138 lines, 4.2KB");
  });

  it("renders tool-progress as …", () => {
    const row = toCompactRow(line({ kind: "tool-progress", toolName: "Grep" }));
    expect(row.glyph).toBe("…");
    expect(row.action).toBe("Grep");
  });

  it("renders reasoning as •", () => {
    const row = toCompactRow(line({ kind: "reasoning", detail: "looking for SSRF" }));
    expect(row.glyph).toBe("•");
    expect(row.action).toBe("thinking");
    expect(row.summary).toBe("looking for SSRF");
  });

  it("renders finding-preview as !", () => {
    const row = toCompactRow(line({ kind: "finding-preview", detail: "SQL injection in /users" }));
    expect(row.glyph).toBe("!");
    expect(row.action).toBe("finding");
    expect(row.summary).toContain("SQL injection");
  });

  it("renders summary as ·", () => {
    const row = toCompactRow(line({ kind: "summary", detail: "done" }));
    expect(row.glyph).toBe("·");
    expect(row.action).toBe("summary");
  });

  it("middle-truncates extra-long target details", () => {
    const long = `src/${"very-deep-path-".repeat(20)}file.ts`;
    const row = toCompactRow(line({ kind: "tool-start", toolName: "Read", detail: long }));
    expect(row.target?.length).toBeLessThanOrEqual(56);
    expect(row.target).toContain("…");
    expect(row.target).toMatch(/file\.ts$/);
  });
});

describe("toTranscriptEntry", () => {
  it("uses BLACK_CIRCLE for tool-start", () => {
    const entry = toTranscriptEntry(line({ kind: "tool-start", toolName: "Read", detail: "x.ts" }));
    expect(entry.glyph).toBe(BLACK_CIRCLE);
    expect(entry.head).toBe("Read(x.ts)");
    expect(entry.inProgress).toBe(true);
  });

  it("uses LOWER_HOOK for tool-complete", () => {
    const entry = toTranscriptEntry(
      line({ kind: "tool-complete", toolName: "Read", detail: "12 lines" }),
    );
    expect(entry.glyph).toBe(LOWER_HOOK);
    expect(entry.head).toBe("Read");
    expect(entry.body).toBe("12 lines");
  });

  it("uses THINKING_GLYPH for reasoning", () => {
    const entry = toTranscriptEntry(line({ kind: "reasoning", detail: "checking sanitizers" }));
    expect(entry.glyph).toBe(THINKING_GLYPH);
    expect(entry.head).toContain("Thinking");
    expect(entry.head).toContain("sanitizers");
  });

  it("uses FINDING_GLYPH for finding-preview", () => {
    const entry = toTranscriptEntry(line({ kind: "finding-preview", detail: "XSS" }));
    expect(entry.glyph).toBe(FINDING_GLYPH);
    expect(entry.head).toContain("Finding");
  });

  it("uses BLACK_CIRCLE for summary prose", () => {
    const entry = toTranscriptEntry(line({ kind: "summary", detail: "complete" }));
    expect(entry.glyph).toBe(BLACK_CIRCLE);
    expect(entry.head).toBe("complete");
  });
});

describe("actorLabelFromFingerprint", () => {
  it("strips slug + suppresses runIndex 0", () => {
    expect(actorLabelFromFingerprint("carlini-threat-hunt:Unauthenticated_User:0")).toBe(
      "Unauthenticated User",
    );
  });

  it("annotates non-zero runIndex", () => {
    expect(actorLabelFromFingerprint("carlini-threat-hunt:External_Attacker:2")).toBe(
      "External Attacker (run 2)",
    );
  });

  it("returns input verbatim for malformed fingerprints", () => {
    expect(actorLabelFromFingerprint("not-a-fingerprint")).toBe("not-a-fingerprint");
  });
});

describe("actorShortId", () => {
  it("derives stable AUTH-01 / DATA-02 style aliases", () => {
    const a = actorShortId("carlini-threat-hunt:Authenticated_User:0", 0);
    expect(a).toMatch(/^AUTH/);
    expect(a).toBe("AUTH-01");
    const b = actorShortId("carlini-threat-hunt:Data_Importer:1", 1);
    expect(b).toBe("DATA-02");
  });

  it("falls back to ACTOR-prefix for non-letter slugs", () => {
    // The slug "123" has no letters, so the fallback "ACTOR" prefix is
    // truncated to the canonical 4-char head.
    expect(actorShortId("carlini-threat-hunt:123:0", 4)).toBe("ACTO-05");
  });
});
