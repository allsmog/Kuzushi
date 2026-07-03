/**
 * Kuzushi TUI Kit — React components that reproduce the Kuzushi terminal
 * (Ratatui) shell's design language: the 8-role theme, severity palette,
 * JetBrains Mono grid, and the growing-console primitives every screen is
 * built from.
 *
 * Import the stylesheet once, then compose screens inside a <TermFrame>:
 *
 *   import "@kuzushi/tui-kit/styles.css";
 *   import { TermFrame, StatusStrip, LogLine, Footer } from "@kuzushi/tui-kit";
 */

export { TermFrame, type TermFrameProps } from "./TermFrame";
export { StatusStrip, type StatusStripProps } from "./StatusStrip";
export { Row, type RowProps } from "./Row";
export { Glyph, type GlyphProps } from "./Glyph";
export { SectionHeader, type SectionHeaderProps } from "./SectionHeader";
export { LogLine, type LogLineProps } from "./LogLine";
export { Footer, type FooterProps, type Keybind } from "./Footer";
export { SeverityBadge, type SeverityBadgeProps } from "./SeverityBadge";
export { PhaseRail, type PhaseRailProps, type Phase, type PhaseState } from "./PhaseRail";
export { ProofBadge, type ProofBadgeProps, type ProofState } from "./ProofBadge";
export { MeterBar, type MeterBarProps } from "./MeterBar";
export {
  ProposalRow,
  type ProposalRowProps,
  type ProposalState,
} from "./ProposalRow";
export { EngineChips, type EngineChipsProps, type EngineChip } from "./EngineChips";
export {
  DEFAULT_THEME_TOKENS,
  HIGH_CONTRAST_THEME_TOKENS,
  LOG_GLYPH,
  THEME_TOKENS,
  type LogKind,
  type Severity,
  type ThemeName,
  type ThemeTokenName,
  type Tone,
  toneClass,
} from "./tokens";
