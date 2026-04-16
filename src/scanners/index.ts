import { AgenticPlugin } from "./agentic.js";
import { CodeQLPlugin } from "./codeql.js";
import { ScannerRegistry } from "./registry.js";
import { SemgrepPlugin } from "./semgrep.js";

export function createDefaultRegistry(): ScannerRegistry {
  const registry = new ScannerRegistry();
  registry.register(new SemgrepPlugin());
  registry.register(new AgenticPlugin());
  registry.register(new CodeQLPlugin());
  return registry;
}

export * from "./registry.js";
export * from "./types.js";
