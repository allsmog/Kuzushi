/**
 * Type contract for per-module home renderers.
 *
 * Each agentic module that wants the v3 "Status / Actions / Last run" home
 * registers a `ModuleHomeRenderer` against its module id. `ModuleHome` falls
 * back to the generic tools table when no renderer is registered.
 */
import type React from "react";
import type { ShellState } from "../../state.js";

export interface ModuleHomeProps {
  shell: ShellState;
}

export interface ModuleHomeRenderer {
  /** Module id this renderer is responsible for (e.g. `"context"`). */
  id: string;
  render: (props: ModuleHomeProps) => React.ReactElement;
}
