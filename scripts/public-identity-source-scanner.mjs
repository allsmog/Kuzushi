import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const ignoredFiles = new Set(["scripts/check-public-identity.mjs", "docs/PORT_PLAN.md"]);
const ignoredPrefixes = ["docs/notes/", "target/", "node_modules/", "dist/", "coverage/"];

export function repoRoot() {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], {
      encoding: "utf8",
    }).trim();
  } catch {
    return process.cwd();
  }
}

export function createPublicIdentitySourceScanner(contract) {
  const lineFailures = createLineFailureScanner(contract);
  return {
    publicFiles: () => publicFiles(contract.root, contract.publicSurfaces),
    scanFile: (file) => scanFile(contract.root, file, lineFailures),
  };
}

export function requiredIdentityReferenceFailures(root, contract) {
  const source = readFileSync(path.join(root, contract.file), "utf8");
  return [...missingNeedleFailures(source, contract), ...forbiddenNeedleFailures(source, contract)];
}

function publicFiles(root, publicSurfaces) {
  return [...new Set([...gitLines(root, ["ls-files"]), ...untrackedFiles(root)])]
    .filter((file) => isPublicSurface(file, publicSurfaces))
    .filter((file) => !isIgnored(file))
    .filter((file) => existsSync(path.join(root, file)))
    .sort();
}

function untrackedFiles(root) {
  return gitLines(root, ["ls-files", "--others", "--exclude-standard"]);
}

function scanFile(root, file, lineFailures) {
  return readFileSync(path.join(root, file), "utf8")
    .split(/\r?\n/)
    .flatMap((line, index) => lineFailures(file, line, index + 1));
}

function createLineFailureScanner(contract) {
  return (file, line, lineNumber) =>
    checksForFile(contract, file)
      .filter(([, pattern]) => pattern.test(line))
      .map(([label]) => `${file}:${lineNumber} ${label}`);
}

function checksForFile(contract, file) {
  return [
    ...contract.forbidden,
    ...(isPublicDoc(file) ? contract.publicDocForbidden : []),
    ...(isProductionPublicSource(file) ? contract.publicSourceForbidden : []),
    ...(isRenderedTuiSnapshot(file) ? contract.renderedUiForbidden : []),
  ];
}

function missingNeedleFailures(source, { label, file, needles }) {
  return needles
    .filter((needle) => !source.includes(needle))
    .map((needle) => `${file}: missing ${label} reference ${needle}`);
}

function forbiddenNeedleFailures(source, { label, file, forbidden = [] }) {
  return forbidden
    .filter((needle) => source.includes(needle))
    .map((needle) => `${file}: forbidden ${label} reference ${needle}`);
}

function gitLines(root, args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" })
    .split(/\r?\n/)
    .map((file) => file.trim())
    .filter(Boolean);
}

function isPublicSurface(file, publicSurfaces) {
  return publicSurfaces.some((candidate) => file === candidate || file.startsWith(`${candidate}/`));
}

function isIgnored(file) {
  return ignoredFiles.has(file) || ignoredPrefixes.some((prefix) => file.startsWith(prefix));
}

function isPublicDoc(file) {
  if (file.startsWith("docs/quality/") || file === "docs/PORT_PLAN.md") return false;
  return file === "README.md" || file.startsWith("docs/");
}

function isProductionPublicSource(file) {
  return file.includes("/src/") && !file.endsWith("/tests.rs") && !file.endsWith("_tests.rs");
}

function isRenderedTuiSnapshot(file) {
  return file.startsWith("crates/kuzushi-tui/tests/snapshots/") && file.endsWith(".snap");
}
