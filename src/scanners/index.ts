import { ScannerRegistry } from "./registry.js";
import { SemgrepPlugin } from "./semgrep.js";
import { ClaudeAdkPlugin } from "./claude-adk.js";
import { CodeQLPlugin } from "./codeql.js";

export function createDefaultRegistry(): ScannerRegistry {
  const registry = new ScannerRegistry();
  registry.register(new SemgrepPlugin());
  registry.register(new ClaudeAdkPlugin());
  registry.register(new CodeQLPlugin());
  return registry;
}

export * from "./types.js";
export * from "./registry.js";
