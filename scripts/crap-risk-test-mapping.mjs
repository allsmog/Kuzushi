import path from "node:path";

const GENERIC_TOKENS = new Set([
  "application",
  "artifact",
  "context",
  "execution",
  "runtime",
  "service",
  "state",
]);

export function testCoversProductionFile(productionFile, testFile, testSource = "") {
  const production = normalize(productionFile);
  const test = normalize(testFile);
  if (scopeRoot(production) !== scopeRoot(test)) return false;
  if (isSiblingTest(production, test)) return true;
  if (matchingBasename(production, test)) return true;
  return semanticTokens(production).some((token) => testSource.toLowerCase().includes(token));
}

function isSiblingTest(production, test) {
  const directory = path.posix.dirname(production);
  return (
    test === `${directory}/tests.rs` ||
    test.startsWith(`${directory}/tests/`) ||
    test === `${directory}/${path.posix.basename(production, ".rs")}_tests.rs`
  );
}

function matchingBasename(production, test) {
  const productionStem = path.posix.basename(production).replace(/\.(?:rs|mjs|js|ts)$/, "");
  const testStem = path.posix
    .basename(test)
    .replace(/(?:[._-]test|[._-]tests)?\.(?:rs|mjs|js|ts)$/, "");
  return productionStem !== "mod" && productionStem === testStem;
}

function semanticTokens(file) {
  return path.posix
    .basename(file)
    .replace(/\.(?:rs|mjs|js|ts)$/, "")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length >= 5 && !GENERIC_TOKENS.has(token));
}

function scopeRoot(file) {
  const parts = file.split("/");
  if (parts[0] === "crates" && parts.length >= 2) return parts.slice(0, 2).join("/");
  if (parts[0] === "src" || parts[0] === "tests") return "typescript-sdk";
  return parts[0] ?? "";
}

function normalize(file) {
  return file.trim().replaceAll("\\", "/");
}
