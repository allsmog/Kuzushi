/**
 * Unit tests for the cursor-centered virtualization window helper.
 *
 * The invariant the helper guarantees:
 *
 *   top <= cursor < bottom && bottom - top == min(total, pageSize)
 *
 * These tests exercise the scroll-by-one, scroll-by-page, cursor-out-of-
 * range, and edge-case behaviours the `FindingsView` consumer relies on.
 */

import { describe, expect, it } from "vitest";
import { computeVisibleSlice } from "../../src/ui/hooks/useVisibleSlice.js";

describe("computeVisibleSlice", () => {
  it("covers the entire list when pageSize >= total", () => {
    const s = computeVisibleSlice({ total: 5, cursor: 0, pageSize: 50 });
    expect(s).toMatchObject({ top: 0, bottom: 5, cursor: 0 });
  });

  it("anchors at top when cursor is already visible", () => {
    const s = computeVisibleSlice({ total: 100, cursor: 5, pageSize: 20 });
    expect(s.top).toBe(0);
    expect(s.bottom).toBe(20);
  });

  it("advances the window when the cursor moves past the current bottom", () => {
    const s = computeVisibleSlice({ total: 100, cursor: 25, pageSize: 20, top: 0 });
    // bottom must be cursor + 1; top = bottom - pageSize.
    expect(s.bottom).toBe(26);
    expect(s.top).toBe(6);
  });

  it("pulls the window up when the cursor moves above the current top", () => {
    const s = computeVisibleSlice({ total: 100, cursor: 3, pageSize: 20, top: 10 });
    expect(s.top).toBe(3);
    expect(s.bottom).toBe(23);
  });

  it("keeps top fixed when the cursor stays inside the window", () => {
    const s = computeVisibleSlice({ total: 100, cursor: 15, pageSize: 20, top: 10 });
    expect(s.top).toBe(10);
    expect(s.bottom).toBe(30);
  });

  it("clamps bottom to total when the cursor approaches the end", () => {
    const s = computeVisibleSlice({ total: 100, cursor: 99, pageSize: 20, top: 70 });
    expect(s.bottom).toBe(100);
    expect(s.top).toBe(80);
  });

  it("clamps a negative cursor to 0", () => {
    const s = computeVisibleSlice({ total: 100, cursor: -5, pageSize: 20 });
    expect(s.cursor).toBe(0);
    expect(s.top).toBe(0);
  });

  it("clamps a cursor past total-1 to total-1", () => {
    const s = computeVisibleSlice({ total: 100, cursor: 500, pageSize: 20 });
    expect(s.cursor).toBe(99);
    expect(s.bottom).toBe(100);
    expect(s.top).toBe(80);
  });

  it("returns an empty window for total=0", () => {
    const s = computeVisibleSlice({ total: 0, cursor: 0, pageSize: 20 });
    expect(s.top).toBe(0);
    expect(s.bottom).toBe(0);
  });

  it("clamps pageSize < 1 to 1", () => {
    const s = computeVisibleSlice({ total: 10, cursor: 0, pageSize: 0 });
    expect(s.pageSize).toBe(1);
    expect(s.bottom - s.top).toBe(1);
  });
});
