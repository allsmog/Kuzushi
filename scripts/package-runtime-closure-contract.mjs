import path from "node:path";

const relativeReferencePatterns = [
  /\bfrom\s+["'](\.{1,2}\/[^"']+)["']/g,
  /\bimport\s+["'](\.{1,2}\/[^"']+)["']/g,
  /\bimport\s*\(\s*["'](\.{1,2}\/[^"']+)["']\s*\)/g,
  /\bnew\s+URL\(\s*["'](\.{1,2}\/[^"']+)["']\s*,\s*import\.meta\.url\s*\)/g,
];

export function packagedRuntimeClosureFailures({
  packageEntries,
  readSource,
  roots = ["scripts/langgraph-bridge.mjs", "scripts/kuzushi-dynamic-module-host.mjs"],
}) {
  const entries = Array.isArray(packageEntries)
    ? packageEntries.filter((entry) => typeof entry === "string" && entry.length > 0)
    : [];
  const failures = [];
  const visited = new Set();
  const queue = [...roots];

  while (queue.length > 0) {
    const current = queue.shift();
    if (visited.has(current)) continue;
    visited.add(current);

    if (!packageEntryCovers(entries, current)) {
      failures.push(`packaged runtime root is not shipped ${current}`);
      continue;
    }

    let source;
    try {
      source = readSource(current);
    } catch (error) {
      failures.push(`packaged runtime source is unreadable ${current}: ${error.message}`);
      continue;
    }

    for (const specifier of relativeRuntimeReferences(source)) {
      const resolved = resolveRelativeRuntimeReference(current, specifier);
      if (resolved === null) {
        failures.push(`packaged runtime reference escapes package root ${current} -> ${specifier}`);
        continue;
      }
      if (!packageEntryCovers(entries, resolved)) {
        failures.push(`packaged runtime reference is not shipped ${current} -> ${resolved}`);
        continue;
      }
      if (resolved.endsWith(".mjs") && !visited.has(resolved)) queue.push(resolved);
    }
  }

  return failures;
}

export function relativeRuntimeReferences(source) {
  const references = relativeReferencePatterns.flatMap((pattern) =>
    [...String(source ?? "").matchAll(pattern)].map((match) => match[1]),
  );
  return [...new Set(references)];
}

function resolveRelativeRuntimeReference(importer, specifier) {
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(importer), specifier));
  if (resolved === ".." || resolved.startsWith("../") || path.posix.isAbsolute(resolved)) return null;
  return resolved;
}

function packageEntryCovers(entries, file) {
  const includes = entries.filter((entry) => !entry.startsWith("!"));
  const excludes = entries.filter((entry) => entry.startsWith("!")).map((entry) => entry.slice(1));
  return includes.some((entry) => covers(entry, file)) && !excludes.some((entry) => covers(entry, file));
}

function covers(entry, file) {
  const normalized = entry.replace(/\/+$/, "");
  return file === normalized || file.startsWith(`${normalized}/`);
}
