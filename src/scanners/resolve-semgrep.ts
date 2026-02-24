import { execFileSync } from "node:child_process";
import { createWriteStream, chmodSync, existsSync, mkdirSync } from "node:fs";
import { pipeline } from "node:stream/promises";
import { get } from "node:https";
import path from "node:path";
import os from "node:os";
import type { IncomingMessage } from "node:http";

const BIN_DIR = path.join(os.homedir(), ".kuzushi", "bin");
const GITHUB_RELEASE_URL =
  "https://api.github.com/repos/opengrep/opengrep/releases/latest";

/** Map Node's process.platform + process.arch to Opengrep asset name. */
function getAssetName(): string {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "darwin" && arch === "arm64") return "opengrep_osx_arm64";
  if (platform === "darwin" && arch === "x64") return "opengrep_osx_x86";
  if (platform === "linux" && arch === "x64") return "opengrep_manylinux_x86";
  if (platform === "linux" && arch === "arm64") return "opengrep_manylinux_aarch64";
  if (platform === "win32" && arch === "x64") return "opengrep_windows_x86.exe";

  throw new Error(
    `Unsupported platform: ${platform}/${arch}. Install semgrep or opengrep manually.`,
  );
}

/** Check if a binary exists on PATH. */
function which(name: string): string | null {
  try {
    return execFileSync("which", [name], { encoding: "utf-8" }).trim() || null;
  } catch {
    return null;
  }
}

/** Follow redirects and return the final response. */
function httpsGet(url: string): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    get(url, { headers: { "User-Agent": "kuzushi/0.1" } }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        httpsGet(res.headers.location).then(resolve, reject);
        return;
      }
      resolve(res);
    }).on("error", reject);
  });
}

/** Fetch latest release info from GitHub. */
async function getLatestReleaseDownloadUrl(assetName: string): Promise<string> {
  const res = await httpsGet(GITHUB_RELEASE_URL);

  const chunks: Buffer[] = [];
  for await (const chunk of res) chunks.push(chunk as Buffer);
  const body = JSON.parse(Buffer.concat(chunks).toString());

  const asset = body.assets?.find(
    (a: { name: string }) => a.name === assetName,
  );
  if (!asset) {
    throw new Error(
      `Could not find asset "${assetName}" in latest opengrep release (${body.tag_name}).`,
    );
  }

  return asset.browser_download_url;
}

/** Download a file from a URL to a local path. */
async function downloadFile(url: string, dest: string): Promise<void> {
  const res = await httpsGet(url);
  if (res.statusCode !== 200) {
    throw new Error(`Download failed: HTTP ${res.statusCode}`);
  }
  await pipeline(res, createWriteStream(dest));
}

/**
 * Resolve the Semgrep-compatible scanner binary path.
 *
 * Precedence:
 * 1. `opengrep` on PATH
 * 2. `semgrep` on PATH
 * 3. Previously downloaded binary at ~/.kuzushi/bin/opengrep
 * 4. Auto-download from GitHub releases
 */
export async function resolveSemgrepBinary(): Promise<string> {
  const onPath = which("opengrep") ?? which("semgrep");
  if (onPath) return onPath;

  const localBin = path.join(BIN_DIR, process.platform === "win32" ? "opengrep.exe" : "opengrep");
  if (existsSync(localBin)) return localBin;

  console.log("  No scanner found on PATH. Downloading opengrep...");
  const assetName = getAssetName();
  const downloadUrl = await getLatestReleaseDownloadUrl(assetName);

  if (!existsSync(BIN_DIR)) mkdirSync(BIN_DIR, { recursive: true });

  console.log(`  Downloading ${assetName}...`);
  await downloadFile(downloadUrl, localBin);

  if (process.platform !== "win32") {
    chmodSync(localBin, 0o755);
  }

  console.log(`  Installed opengrep to ${localBin}`);
  return localBin;
}
