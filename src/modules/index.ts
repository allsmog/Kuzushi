export { createCoreSastModule } from "./core-sast.js";
export { ModuleRegistry, parseModuleSpecifier } from "./registry.js";
export type {
  CopilotModule,
  JSONSchema,
  ModuleCategory,
  ModuleContext,
  ModuleInfo,
  ModuleManifest,
  ModuleRequirements,
  ModuleSpecifier,
  ModuleTool,
  ToolExecutionContext,
  ToolResult,
} from "./types.js";
export { createVariantHunterModule } from "./variant-hunter.js";
