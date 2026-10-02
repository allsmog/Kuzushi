// The published bridge ships as a module graph, not a flat list. Every module
// `scripts/langgraph-bridge.mjs` can reach has to appear in package.json
// `files`, or the published CLI dies with ERR_MODULE_NOT_FOUND the first time
// an operator runs an agentic tool. Deriving the closure from the sources keeps
// the packaging contract honest instead of asking an author to remember a list.
import path from "node:path";

export const BRIDGE_ENTRYPOINT = "scripts/langgraph-bridge.mjs";

// `from "./x.mjs"` covers static import, `export … from`, and bare
// side-effect import; `import("./x.mjs")` covers the dynamic form. All three
// quote styles count, because a template literal is a valid specifier too.
const IMPORT_SITE = /(?:\bfrom|\bimport)\s*\(?\s*(["'`])(\.{1,2}\/[^"'`\n]*)\1/g;
// A worker or asset the bridge resolves at runtime ships just like an import.
const RUNTIME_URL_SITE = /\bnew\s+URL\s*\(\s*(["'`])(\.{1,2}\/[^"'`\n]*)\1/g;

export function bridgeModuleReferences(source) {
  const references = [
    ...relativeSpecifiers(source, IMPORT_SITE),
    ...relativeSpecifiers(source, RUNTIME_URL_SITE),
  ].map(bridgeModuleReference);
  return {
    modules: references.flatMap((reference) => (reference.module ? [reference.module] : [])),
    unresolvable: references.flatMap((reference) =>
      reference.unresolvable ? [reference.unresolvable] : [],
    ),
  };
}

// A `?worker`/`#fragment` suffix is a loader hint rather than part of the path.
// Interpolation leaves the target unknowable, so it is reported instead of
// being dropped: a silently unseen specifier is the exemption this contract
// exists to close, and only the author can make the reference literal.
export function bridgeModuleReference(specifier) {
  const target = specifier.replace(/[?#].*$/, "");
  if (target.includes("${")) return { unresolvable: specifier };
  return target.endsWith(".mjs") ? { module: target } : {};
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
    const references = bridgeModuleReferences(readBridgeModule(readModule, module, failures));
    failures.push(...unresolvableFailures(module, references.unresolvable));
    pending.push(...references.modules.map((specifier) => resolveBridgeModule(module, specifier)));
  }
  return { modules: modules.sort(), failures };
}

function unresolvableFailures(module, unresolvable) {
  return unresolvable.map(
    (specifier) =>
      `shipped bridge module ${module} references ${specifier}, which the packaging contract cannot resolve: keep bridge module specifiers literal`,
  );
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
