/**
 * ExpandableSection — progressive-disclosure container.
 *
 * Default collapsed; space or Enter toggles. Keeps dense detail off-screen
 * until the user opts in. Used to tame FindingCard and AgentActivity.
 */
import { Box, Text } from "ink";
import type { FC, ReactNode } from "react";
import { useExpanded } from "../hooks/useExpanded.js";
import { SPACING, tokens } from "../tokens.js";

export interface ExpandableSectionProps {
  summary: ReactNode;
  children: ReactNode;
  defaultExpanded?: boolean;
  expanded?: boolean;
  caret?: { collapsed: string; expanded: string };
  hint?: string;
  isActive?: boolean;
}

const DEFAULT_CARET = { collapsed: "\u25B8", expanded: "\u25BE" };

export const ExpandableSection: FC<ExpandableSectionProps> = ({
  summary,
  children,
  defaultExpanded = false,
  expanded: controlled,
  caret = DEFAULT_CARET,
  hint = "(press space to expand)",
  isActive = true,
}) => {
  const internal = useExpanded({
    initial: defaultExpanded,
    isActive: isActive && controlled === undefined,
  });
  const expanded = controlled ?? internal.expanded;
  const caretChar = expanded ? caret.expanded : caret.collapsed;
  const caretColor = isActive ? tokens.accent : tokens.muted;

  return (
    <Box flexDirection="column">
      <Box>
        <Text>
          {caretColor(caretChar)} {typeof summary === "string" ? summary : null}
        </Text>
        {typeof summary !== "string" ? <Box marginLeft={SPACING.sm}>{summary}</Box> : null}
        {!expanded && hint ? (
          <Box marginLeft={SPACING.md}>
            <Text>{tokens.hint(hint)}</Text>
          </Box>
        ) : null}
      </Box>
      {expanded ? (
        <Box flexDirection="column" paddingLeft={SPACING.md}>
          {children}
        </Box>
      ) : null}
    </Box>
  );
};
