/**
 * Breadcrumb — persistent wayfinding for nested CLI flows.
 *
 * Renders: `Setup \u203A Credentials \u203A Input   (step 2/5)`
 */
import { Box, Text } from "ink";
import type { FC } from "react";
import { tokens } from "../tokens.js";

export interface BreadcrumbProps {
  segments: ReadonlyArray<string>;
  currentStep?: number;
  totalSteps?: number;
  separator?: string;
  maxWidth?: number;
}

const ELLIPSIS = "\u2026";

export const Breadcrumb: FC<BreadcrumbProps> = ({
  segments,
  currentStep,
  totalSteps,
  separator = " \u203A ",
  maxWidth,
}) => {
  if (segments.length === 0) return null;

  const showStep = typeof currentStep === "number" && typeof totalSteps === "number";
  const stepSuffix = showStep ? `  (step ${currentStep}/${totalSteps})` : "";

  let visible: string[] = [...segments];
  let collapsed = false;
  if (typeof maxWidth === "number" && maxWidth > 0) {
    const joinedLen = (segs: string[]) => segs.join(separator).length + stepSuffix.length;
    while (visible.length > 1 && joinedLen(visible) > maxWidth) {
      visible = visible.slice(1);
      collapsed = true;
    }
    if (collapsed) {
      const last = visible[visible.length - 1] ?? "";
      visible = [ELLIPSIS, last];
    }
  }

  const lastIdx = visible.length - 1;

  return (
    <Box>
      <Text>
        {visible
          .map((seg, i) => {
            const isLast = i === lastIdx;
            const styled = isLast ? tokens.strong(seg) : tokens.muted(seg);
            const sep = i > 0 ? tokens.subtle(separator) : "";
            return `${sep}${styled}`;
          })
          .join("")}
        {showStep ? tokens.hint(stepSuffix) : ""}
      </Text>
    </Box>
  );
};
