// The published bridge ships as a module graph, not a flat list. Every module
// `scripts/langgraph-bridge.mjs` can reach has to appear in package.json
// `files`, or the published CLI dies with ERR_MODULE_NOT_FOUND the first time
// an operator runs an agentic tool. Deriving the closure from the sources keeps
// the packaging contract honest instead of asking an author to remember a list.
import path from "node:path";

export const BRIDGE_ENTRYPOINT = "scripts/langgraph-bridge.mjs";

// `from "./x.mjs"` covers static import, `export … from`, and bare
// side-effect import; `import("./x.mjs")` covers the dynamic form.
const IMPORT_SPECIFIER = /(?:\bfrom|\bimport)\s*\(?\s*(["'])(\.{1,2}\/[^"'\n]*\.mjs)\1/g;
// A worker or asset the bridge resolves at runtime ships just like an import.
const RUNTIME_URL_SPECIFIER = /\bnew\s+URL\s*\(\s*(["'])(\.{1,2}\/[^"'\n]*\.mjs)\1/g;

export function bridgeModuleReferences(source) {
  return [
    ...relativeSpecifiers(source, IMPORT_SPECIFIER),
    ...relativeSpecifiers(source, RUNTIME_URL_SPECIFIER),
  ];
}

export function resolveBridgeModule(fromModule, specifier) {
  return path.posix.join(path.posix.dirname(fromModule), specifier);
}

export function bridgeModuleClosure(readModule, entrypoint = BRIDGE_ENTRYPOINT) {
  const modules = [];
  const failures = [];
  const pending = [entrypoint];
  const visited = new Set();
  while (pending.length > 0) {
    const module = pending.shift();
    if (visited.has(module)) continue;
    visited.add(module);
    modules.push(module);
    const source = readBridgeModule(readModule, module, failures);
    pending.push(...referencedModules(module, source));
  }
  return { modules: modules.sort(), failures };
}

function referencedModules(module, source) {
  return bridgeModuleReferences(source).map((specifier) => resolveBridgeModule(module, specifier));
}

// An unreadable module is reported rather than thrown: the caller is a contract
// report, so a missing bridge module belongs in its failure list.
function readBridgeModule(readModule, module, failures) {
  try {
    return readModule(module);
  } catch (error) {
    failures.push(`shipped bridge module ${module} must be readable: ${error.message}`);
    return "";
  }
}

function relativeSpecifiers(source, pattern) {
  return [...source.matchAll(pattern)].map((match) => match[2]);
}
