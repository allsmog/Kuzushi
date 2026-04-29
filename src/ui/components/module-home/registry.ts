/**
 * Lookup table for per-module home renderers.
 *
 * Modules opt in by registering their renderer against the module id.
 * When `ModuleHome.tsx` doesn't find a match here it falls back to the
 * legacy tools table. Keep this barrel side-effect-free — components are
 * referenced by id, not by import-time registration.
 */

import { CarliniThreatHuntHome } from "./carlini-threat-hunt-home.js";
import { ContextHome } from "./context-home.js";
import { ThreatModelHome } from "./threat-model-home.js";
import type { ModuleHomeRenderer } from "./types.js";
import { VendorAssessmentHome } from "./vendor-assessment-home.js";

export const MODULE_HOME_RENDERERS: ReadonlyArray<ModuleHomeRenderer> = [
  { id: "context", render: ContextHome },
  { id: "carlini-threat-hunt", render: CarliniThreatHuntHome },
  { id: "threat-model", render: ThreatModelHome },
  { id: "vendor-assessment", render: VendorAssessmentHome },
];

export function getModuleHomeRenderer(moduleId: string | null): ModuleHomeRenderer | undefined {
  if (!moduleId) return undefined;
  return MODULE_HOME_RENDERERS.find((r) => r.id === moduleId);
}
