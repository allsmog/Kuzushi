/**
 * ConfirmDialog — two-choice yes/no prompt with arrow toggle + letter shortcuts.
 *
 * No such primitive existed before; previously each consent prompt
 * reimplemented its own key handler with inconsistent affordances.
 */
import { Box, Text, useInput } from "ink";
import type { FC } from "react";
import { useState } from "react";
import { tokens } from "../tokens.js";

export interface ConfirmDialogProps {
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
  confirmLabel?: string;
  cancelLabel?: string;
  defaultChoice?: "confirm" | "cancel";
  isActive?: boolean;
}

export const ConfirmDialog: FC<ConfirmDialogProps> = ({
  message,
  onConfirm,
  onCancel,
  confirmLabel = "Yes",
  cancelLabel = "No",
  defaultChoice = "cancel",
  isActive = true,
}) => {
  const [choice, setChoice] = useState<"confirm" | "cancel">(defaultChoice);

  useInput(
    (input, key) => {
      if (key.leftArrow || key.upArrow) {
        setChoice("confirm");
      } else if (key.rightArrow || key.downArrow || key.tab) {
        setChoice("cancel");
      } else if (input === "y" || input === "Y") {
        onConfirm();
      } else if (input === "n" || input === "N" || key.escape) {
        onCancel();
      } else if (key.return) {
        (choice === "confirm" ? onConfirm : onCancel)();
      }
    },
    { isActive },
  );

  const renderBtn = (label: string, active: boolean) => {
    const padded = ` ${label} `;
    return active ? tokens.strong(`[${label}]`) : tokens.muted(` ${label} `);
  };

  return (
    <Box flexDirection="column">
      <Box>
        <Text>{tokens.label(message)}</Text>
      </Box>
      <Box marginTop={1}>
        <Text>
          {renderBtn(confirmLabel, choice === "confirm")}
          {"   "}
          {renderBtn(cancelLabel, choice === "cancel")}
        </Text>
      </Box>
      <Box marginTop={1}>
        <Text>
          {tokens.hint("[\u2190/\u2192] toggle  [Y/N] shortcut  [Enter] submit  [Esc] cancel")}
        </Text>
      </Box>
    </Box>
  );
};
