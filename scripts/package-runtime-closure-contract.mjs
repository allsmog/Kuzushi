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
  const entries = declaredPackageEntries(packageEntries);
  const failures = [];
  const visited = new Set();
  const queue = [...roots];

  while (queue.length > 0) {
    const current = queue.shift();
    if (visited.has(current)) continue;
    visited.add(current);

    const outcome = packagedRuntimeModuleOutcome(entries, readSource, current);
    failures.push(...outcome.failures);
    queue.push(...outcome.dependencies.filter((dependency) => !visited.has(dependency)));
  }

  return failures;
}

export function relativeRuntimeReferences(source) {
  const references = relativeReferencePatterns.flatMap((pattern) =>
    [...String(source ?? "").matchAll(pattern)].map((match) => match[1]),
  );
  return [...new Set(references)];
}

function declaredPackageEntries(packageEntries) {
  if (!Array.isArray(packageEntries)) return [];
  return packageEntries.filter((entry) => typeof entry === "string" && entry.length > 0);
}

function packagedRuntimeModuleOutcome(entries, readSource, file) {
  if (!packageEntryCovers(entries, file)) {
    return { failures: [`packaged runtime root is not shipped ${file}`], dependencies: [] };
  }

  const read = readPackagedRuntimeSource(readSource, file);
  if (read.failure) return { failures: [read.failure], dependencies: [] };

  const outcomes = relativeRuntimeReferences(read.source).map((specifier) =>
    packagedRuntimeReferenceOutcome(entries, file, specifier),
  );
  return {
    failures: outcomes.map((outcome) => outcome.failure).filter(Boolean),
    dependencies: outcomes.map((outcome) => outcome.dependency).filter(Boolean),
  };
}

function readPackagedRuntimeSource(readSource, file) {
  try {
    return { source: readSource(file) };
  } catch (error) {
    return { failure: `packaged runtime source is unreadable ${file}: ${error.message}` };
  }
}

function packagedRuntimeReferenceOutcome(entries, importer, specifier) {
  const resolved = resolveRelativeRuntimeReference(importer, specifier);
  if (resolved === null) {
    return {
      failure: `packaged runtime reference escapes package root ${importer} -> ${specifier}`,
    };
  }
  if (!packageEntryCovers(entries, resolved)) {
    return { failure: `packaged runtime reference is not shipped ${importer} -> ${resolved}` };
  }
  if (resolved.endsWith(".mjs")) return { dependency: resolved };
  return {};
}

function resolveRelativeRuntimeReference(importer, specifier) {
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(importer), specifier));
  if (resolved === ".." || resolved.startsWith("../") || path.posix.isAbsolute(resolved))
    return null;
  return resolved;
}

function packageEntryCovers(entries, file) {
  const includes = entries.filter((entry) => !entry.startsWith("!"));
  const excludes = entries.filter((entry) => entry.startsWith("!")).map((entry) => entry.slice(1));
  return (
    includes.some((entry) => covers(entry, file)) && !excludes.some((entry) => covers(entry, file))
  );
}

function covers(entry, file) {
  const normalized = entry.replace(/\/+$/, "");
  return file === normalized || file.startsWith(`${normalized}/`);
}
