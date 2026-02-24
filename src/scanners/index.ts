import { ScannerRegistry } from "./registry.js";
import { SemgrepPlugin } from "./semgrep.js";
import { ClaudeAdkPlugin } from "./claude-adk.js";

export function createDefaultRegistry(): ScannerRegistry {
  const registry = new ScannerRegistry();
  registry.register(new SemgrepPlugin());
  registry.register(new ClaudeAdkPlugin());
  return registry;
}

export * from "./types.js";
export * from "./registry.js";
