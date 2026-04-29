/**
 * InteractionErrorBoundary — render-time poka-yoke for Ink.
 *
 * React error boundaries do not catch event-handler failures, but they do
 * prevent component render crashes from dumping a raw stack into the terminal.
 */

import { Box } from "ink";
import React from "react";
import { SPACING } from "../tokens.js";
import { ErrorCard } from "./ErrorCard.js";

interface InteractionErrorBoundaryProps {
  children: React.ReactNode;
  label?: string;
  hint?: string;
}

interface InteractionErrorBoundaryState {
  error: unknown;
}

export class InteractionErrorBoundary extends React.Component<
  InteractionErrorBoundaryProps,
  InteractionErrorBoundaryState
> {
  state: InteractionErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: unknown): InteractionErrorBoundaryState {
    return { error };
  }

  componentDidCatch(): void {
    // Ink will render the card below. Avoid console.error stack spam.
  }

  componentDidUpdate(prevProps: InteractionErrorBoundaryProps): void {
    if (this.state.error && prevProps.children !== this.props.children) {
      this.setState({ error: null });
    }
  }

  render(): React.ReactNode {
    if (this.state.error) {
      const message =
        this.state.error instanceof Error
          ? this.state.error.message || this.state.error.name
          : "The terminal UI hit an unexpected render error.";
      const label = this.props.label ?? "UI";
      return (
        <Box flexDirection="column" marginTop={SPACING.sm}>
          <ErrorCard
            message={`${label} failed: ${message}`}
            error={this.state.error}
            hint={this.props.hint ?? "Press Esc or /back if available, then retry the command."}
            code="E_UI_RENDER"
          />
        </Box>
      );
    }
    return this.props.children;
  }
}
