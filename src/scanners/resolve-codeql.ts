import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const BIN_DIR = path.join(os.homedir(), ".kuzushi", "bin");
const COMMON_CODEQL_BINARIES = ["/opt/homebrew/bin/codeql", "/usr/local/bin/codeql"] as const;

function which(name: string): string | null {
  try {
    return execFileSync("which", [name], { encoding: "utf-8", timeout: 5000 }).trim() || null;
  } catch {
    return null;
  }
}

/**
 * Resolve the CodeQL binary path.
 *
 * Precedence:
 * 1. `codeql` on PATH
 * 2. Cached binary at ~/.kuzushi/bin/codeql
 * 3. Common Homebrew symlink paths that may be outside non-interactive PATH
 * 4. Fail with installation guidance
 */
export async function resolveCodeQLBinary(): Promise<string> {
  const onPath = which("codeql");
  if (onPath) {
    return onPath;
  }

  const cached = path.join(BIN_DIR, process.platform === "win32" ? "codeql.exe" : "codeql");
  if (existsSync(cached)) {
    return cached;
  }

  for (const candidate of COMMON_CODEQL_BINARIES) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  throw new Error(
    [
      "CodeQL CLI not found. Install it:",
      "  gh extension install github/gh-codeql && gh codeql install-stub",
      "  Or download from:",
      "  https://github.com/github/codeql-cli-binaries/releases",
    ].join("\n"),
  );
}
