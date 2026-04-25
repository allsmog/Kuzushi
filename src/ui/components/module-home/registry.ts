/**
 * Lookup table for per-module home renderers.
 *
 * Modules opt in by registering their renderer against the module id.
 * When `ModuleHome.tsx` doesn't find a match here it falls back to the
 * legacy tools table. Keep this barrel side-effect-free — components are
 * referenced by id, not by import-time registration.
 */
import { ContextHome } from "./context-home.js";
import { ThreatHuntHome } from "./threat-hunt-home.js";
import type { ModuleHomeRenderer } from "./types.js";

export const MODULE_HOME_RENDERERS: ReadonlyArray<ModuleHomeRenderer> = [
  { id: "context", render: ContextHome },
  { id: "threat-hunt", render: ThreatHuntHome },
];

export function getModuleHomeRenderer(moduleId: string | null): ModuleHomeRenderer | undefined {
  if (!moduleId) return undefined;
  return MODULE_HOME_RENDERERS.find((r) => r.id === moduleId);
}
