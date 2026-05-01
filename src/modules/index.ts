/**
 * Public surface for `kuzushi/modules`.
 *
 * Third-party module authors `import { defineModule, defineTool } from
 * "kuzushi/modules"` and write their CopilotModule against this surface.
 * Stable exports here are covered by semver; unstable internals must be
 * imported from deeper paths (and may move without a major bump).
 */

// Built-in module factories (consumed by src/copilot/core.ts).
export { createCoreSastModule } from "./core-sast.js";
export type { DefineDagToolSpec, DefineModuleSpec, DefineToolSpec } from "./define.js";
// Authoring helpers — the recommended way to build a module.
export { defineDagTool, defineModule, defineTool } from "./define.js";
export type { ModuleLoadErrorCode } from "./errors.js";
// Structured load-time error type + its discriminator.
export { ModuleLoadError } from "./errors.js";
// Narrow host-handle interfaces exposed via ExecutionContext.
export type {
  HostCapability,
  HostInfo,
  HostUiHandle,
  ModuleEventHandler,
  ModuleEventPayload,
  ModuleEventScope,
  ToolLogger,
  ToolOptionStore,
  UiStatePatch,
  WorkspaceHandle,
  WorkspaceHostStore,
  WorkspaceNoteStore,
  WorkspaceServiceStore,
  WorkspaceVulnStore,
} from "./host-handles.js";
export { createNDayDiffHunterModule } from "./n-day-diff-hunter.js";
// Registry + specifier parsing — re-export so third parties can do static
// analysis of their own module specifiers without importing deep paths.
export { ModuleRegistry, parseModuleSpecifier } from "./registry.js";
export { createSecretScanModule } from "./secret-scan/secret-scan.js";
export type {
  RankedTaintIrisNextCweCatalogEntry,
  TaintIrisNextAgentCweSelection,
  TaintIrisNextBackendHints,
  TaintIrisNextCweCatalogEntry,
  TaintIrisNextSelectionValidation,
  TaintIrisNextStructuralQuery,
} from "./taint-iris-next/cwe-reference.js";
export {
  buildStructuralQueriesFromCatalog,
  filterCatalogForContext,
  rankCatalogEntries,
  renderCatalogForPrompt,
  TAINT_IRIS_NEXT_CWE_CATALOG,
  TAINT_IRIS_NEXT_CWE_CATALOG_BY_ID,
  validateAgentCweSelections,
} from "./taint-iris-next/cwe-reference.js";
export { createTaintIrisNextModule } from "./taint-iris-next/taint-iris-next.js";
export { createThreatModelModule } from "./threat-model/threat-model.js";
// Core types — these are the shape third parties implement.
export type {
  CopilotModule,
  CopilotModuleRequirement,
  DagContext,
  DagTool,
  DagToolSpec,
  ExecutionContext,
  JSONSchema,
  ModuleCategory,
  ModuleContext,
  ModuleInfo,
  ModuleManifest,
  ModuleNotes,
  ModuleRank,
  ModuleReference,
  ModuleRequirements,
  ModuleSpecifier,
  ModuleTool,
  ToolResult,
} from "./types.js";
export { requireDag } from "./types.js";
export { createVariantHunterModule } from "./variant-hunter.js";
export type {
  VendorAssessmentDocument,
  VendorAssessmentDocumentKind,
  VendorAssessmentHomeSlice,
  VendorAssessmentProfile,
  VendorAssessmentReportJson,
  VendorAssessmentScope,
} from "./vendor-assessment/types.js";
export { createVendorAssessmentModule } from "./vendor-assessment/vendor-assessment.js";
export { createXRayModule } from "./x-ray/x-ray.js";
