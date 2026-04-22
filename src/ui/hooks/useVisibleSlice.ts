/**
 * useVisibleSlice — cursor-centered window over a long list.
 *
 * Given `total`, `cursor`, and `pageSize`, return `[top, bottom)` such that
 * the cursor stays on-screen as it moves. The classic scrollview invariant:
 *
 *   top <= cursor < bottom
 *   bottom - top == min(total, pageSize)
 *
 * Pure function — no React state, no Ink hooks. Keeping it pure makes it
 * trivially testable and reusable across views that want their own scroll
 * state (e.g. Threat* views can adopt this without refactoring).
 */

export interface VisibleSlice {
  top: number;
  bottom: number;
  cursor: number;
  pageSize: number;
  total: number;
}

export interface ComputeVisibleSliceArgs {
  total: number;
  cursor: number;
  pageSize: number;
  /**
   * Existing top; lets the window "stick" until the cursor actually leaves
   * the visible range, instead of re-centering on every move. Defaults to 0.
   */
  top?: number;
}

/**
 * Compute a windowed `[top, bottom)` that contains the cursor.
 *
 * Behaviour:
 *   - Cursor above existing top: top = cursor, bottom = cursor + pageSize.
 *   - Cursor below existing bottom: bottom = cursor + 1, top = bottom - pageSize.
 *   - Cursor already inside the window: keep top as-is.
 *   - `pageSize >= total`: window covers everything.
 *   - Always clamps to [0, total].
 */
export function computeVisibleSlice(args: ComputeVisibleSliceArgs): VisibleSlice {
  const total = Math.max(0, args.total | 0);
  const pageSize = Math.max(1, args.pageSize | 0);
  const cursor = clamp(args.cursor | 0, 0, Math.max(0, total - 1));
  const currentTop = Math.max(0, args.top ?? 0);

  if (total <= pageSize) {
    return { top: 0, bottom: total, cursor, pageSize, total };
  }

  let top = currentTop;
  let bottom = top + pageSize;

  if (cursor < top) {
    top = cursor;
    bottom = top + pageSize;
  } else if (cursor >= bottom) {
    bottom = cursor + 1;
    top = bottom - pageSize;
  }

  // Clamp bottom to total and re-derive top so the window doesn't overrun.
  if (bottom > total) {
    bottom = total;
    top = Math.max(0, bottom - pageSize);
  }
  if (top < 0) {
    top = 0;
    bottom = Math.min(total, pageSize);
  }

  return { top, bottom, cursor, pageSize, total };
}

function clamp(n: number, lo: number, hi: number): number {
  return n < lo ? lo : n > hi ? hi : n;
}
