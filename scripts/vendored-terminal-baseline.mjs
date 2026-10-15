import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

const PREFIX = "third-party/crossterm/";
const ARCHIVE = "third-party/upstream/crossterm-0.29.0.crate";
const CHECKSUM = "d8b9f2e4c67f833b660cdb0a3523065869fb35570177239812ed4c905aeff87b";
const OWNED_TEST = "src/event/source/unix/kuzushi_parser_tests.rs";
const PATCHED_INPUTS = new Set([
  "src/event/source/unix/mio.rs",
  "src/event/source/unix/tty.rs",
  "Cargo.lock",
]);
const archives = new Map();

export function vendoredTerminalBaseline(root, file) {
  if (!file.startsWith(PREFIX)) return null;
  const relative = file.slice(PREFIX.length);
  if (relative === OWNED_TEST) return null;
  const archive = authenticateArchive(root);
  const original = upstreamEntry(archive, relative);
  if (!PATCHED_INPUTS.has(relative)) {
    assertUnchangedFile(root, relative, original);
  }
  return original.toString("utf8");
}

function upstreamEntry(archive, relative) {
  return execFileSync("tar", ["-xOzf", archive, `crossterm-0.29.0/${relative}`], {
    maxBuffer: 2 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function assertUnchangedFile(root, relative, original) {
  const current = readFileSync(path.join(root, PREFIX, relative));
  if (!current.equals(original))
    throw new Error(`Unexpected vendored terminal change: ${relative}`);
}

export function verifyVendoredTerminal(root) {
  const archive = authenticateArchive(root);
  const entries = execFileSync("tar", ["-tzf", archive], { encoding: "utf8" }).trim().split("\n");
  const unchanged = entries
    .map((entry) => entry.slice("crossterm-0.29.0/".length))
    .filter((entry) => !entry.endsWith("/") && !PATCHED_INPUTS.has(entry));
  for (const relative of unchanged)
    assertUnchangedFile(root, relative, upstreamEntry(archive, relative));
  return unchanged.length;
}

function authenticateArchive(root) {
  if (archives.has(root)) return archives.get(root);
  const archive = path.join(root, ARCHIVE);
  const checksum = createHash("sha256").update(readFileSync(archive)).digest("hex");
  if (checksum !== CHECKSUM)
    throw new Error("Vendored terminal upstream archive checksum mismatch");
  archives.set(root, archive);
  return archive;
}

export function locallyChangedFunctions(blocks, upstreamBlocks) {
  const unchanged = new Set(upstreamBlocks.map((block) => block.source));
  return blocks.filter((block) => !unchanged.has(block.source));
}
