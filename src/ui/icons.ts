/**
 * Unicode icon constants for terminal display.
 * All characters are in the Basic Multilingual Plane for maximum terminal compatibility.
 */
export const icons = {
  // Status
  success: "\u2713", // ✓
  error: "\u2717", // ✗
  warning: "\u26A0", // ⚠
  info: "\u2139", // ℹ
  pending: "\u25CB", // ○
  active: "\u25CF", // ●
  complete: "\u25C6", // ◆

  // Connectors
  arrow: "\u2192", // →
  ellipsis: "\u22EF", // ⋯
  bullet: "\u2022", // •
  dot: "\u00B7", // ·

  // Tree drawing
  treeMiddle: "\u251C\u2500", // ├─
  treeLast: "\u2514\u2500", // └─
  treePipe: "\u2502", // │

  // Box drawing (sharp corners — Kuzushi style)
  boxTopLeft: "\u250C", // ┌
  boxTopRight: "\u2510", // ┐
  boxBottomLeft: "\u2514", // └
  boxBottomRight: "\u2518", // ┘
  boxHorizontal: "\u2500", // ─
  boxVertical: "\u2502", // │
  boxDividerLeft: "\u251C", // ├
  boxDividerRight: "\u2524", // ┤

  // Stage icons
  lightning: "\u26A1", // ⚡
  shield: "\u25C6", // ◆
  gear: "\u2699", // ⚙
} as const;
