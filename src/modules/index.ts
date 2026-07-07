/**
 * Public surface for `kuzushi/modules`.
 *
 * Third-party module authors `import { defineModule, defineTool } from
 * "kuzushi/modules"` and write their CopilotModule against this surface.
 * Stable exports here are covered by semver; unstable internals must be
 * imported from deeper paths (and may move without a major bump).
 */

import type { CopilotModule } from "./types.js";

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
// KWP MCP composition types — modules use these when refining ExecutionContext
// for host-mounted MCP aliases such as `symcc`.
export type {
  KwpMcpExecutionContext,
  McpArtifactRef,
  McpCallLimits,
  McpCallOptions,
  McpCallResult,
  McpContentBlock,
  McpHandle,
} from "./kwp-mcp.js";
export { McpNotGrantedError, requireMcp } from "./kwp-mcp.js";
// Registry + specifier parsing — re-export so third parties can do static
// analysis of their own module specifiers without importing deep paths.
export { ModuleRegistry, parseModuleSpecifier } from "./registry.js";
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
export type {
  VendorAssessmentDocument,
  VendorAssessmentDocumentKind,
  VendorAssessmentHomeSlice,
  VendorAssessmentProfile,
  VendorAssessmentReportJson,
  VendorAssessmentScope,
} from "./vendor-assessment/types.js";

function retiredBuiltinFactory(name: string): CopilotModule {
  throw new Error(
    `${name} was a TypeScript built-in module factory and is retired from the public SDK after the Rust cutover. Use the Rust CLI/TUI built-ins, or author a third-party module with defineModule/defineTool.`,
  );
}

export function createCoreSastModule(): CopilotModule {
  return retiredBuiltinFactory("createCoreSastModule");
}

export function createNDayDiffHunterModule(): CopilotModule {
  return retiredBuiltinFactory("createNDayDiffHunterModule");
}

export function createSecretScanModule(): CopilotModule {
  return retiredBuiltinFactory("createSecretScanModule");
}

export function createTaintIrisNextModule(): CopilotModule {
  return retiredBuiltinFactory("createTaintIrisNextModule");
}

export function createThreatModelModule(): CopilotModule {
  return retiredBuiltinFactory("createThreatModelModule");
}

export function createVariantHunterModule(): CopilotModule {
  return retiredBuiltinFactory("createVariantHunterModule");
}

export function createVendorAssessmentModule(): CopilotModule {
  return retiredBuiltinFactory("createVendorAssessmentModule");
}

export function createXRayModule(): CopilotModule {
  return retiredBuiltinFactory("createXRayModule");
}
