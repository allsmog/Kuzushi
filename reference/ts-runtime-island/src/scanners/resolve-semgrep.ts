import { execFileSync } from "node:child_process";
import { chmodSync, createWriteStream, existsSync, mkdirSync, unlinkSync } from "node:fs";
import type { IncomingMessage } from "node:http";
import { get } from "node:https";
import os from "node:os";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { getHttpsAgent } from "../http-agent.js";
import { emitOutputNotice } from "../ui/output.js";

const BIN_DIR = path.join(os.homedir(), ".kuzushi", "bin");
const GITHUB_RELEASE_URL = "https://api.github.com/repos/opengrep/opengrep/releases/latest";
const MAX_REDIRECTS = 10;
const REQUEST_TIMEOUT_MS = 30_000;

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
    return execFileSync("which", [name], { encoding: "utf-8", timeout: 5000 }).trim() || null;
  } catch {
    return null;
  }
}

/** Follow redirects and return the final response. */
function httpsGet(url: string, redirectCount: number = 0): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    const req = get(
      url,
      { agent: getHttpsAgent(), headers: { "User-Agent": "kuzushi/0.1" } },
      (res) => {
        if (
          res.statusCode &&
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          typeof res.headers.location === "string"
        ) {
          if (redirectCount >= MAX_REDIRECTS) {
            res.resume();
            reject(new Error(`Too many redirects while fetching ${url}`));
            return;
          }

          const redirectUrl = new URL(res.headers.location, url).toString();
          if (!redirectUrl.startsWith("https://")) {
            res.resume();
            reject(new Error(`Refusing to follow non-HTTPS redirect: ${redirectUrl}`));
            return;
          }
          res.resume();
          httpsGet(redirectUrl, redirectCount + 1).then(resolve, reject);
          return;
        }

        res.setTimeout(REQUEST_TIMEOUT_MS, () => {
          res.destroy(new Error(`Request timed out after ${REQUEST_TIMEOUT_MS}ms: ${url}`));
        });
        resolve(res);
      },
    );

    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error(`Request timed out after ${REQUEST_TIMEOUT_MS}ms: ${url}`));
    });
    req.on("error", reject);
  });
}

/** Fetch latest release info from GitHub. */
async function getLatestReleaseDownloadUrl(assetName: string): Promise<string> {
  const res = await httpsGet(GITHUB_RELEASE_URL);

  const chunks: Buffer[] = [];
  for await (const chunk of res) chunks.push(chunk as Buffer);
  const body = JSON.parse(Buffer.concat(chunks).toString());

  const asset = body.assets?.find((a: { name: string }) => a.name === assetName);
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
    res.resume();
    throw new Error(`Download failed: HTTP ${res.statusCode}`);
  }

  try {
    await pipeline(res, createWriteStream(dest));
  } catch (error) {
    try {
      unlinkSync(dest);
    } catch {
      // Best-effort cleanup for partial downloads.
    }
    throw error;
  }
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

  emitOutputNotice({
    level: "warning",
    message: "Scanner binary not found on PATH",
    detail: "Downloading opengrep...",
    source: "semgrep",
  });
  const assetName = getAssetName();
  const downloadUrl = await getLatestReleaseDownloadUrl(assetName);

  if (!existsSync(BIN_DIR)) mkdirSync(BIN_DIR, { recursive: true });

  emitOutputNotice({
    level: "info",
    message: "Downloading opengrep",
    detail: assetName,
    source: "semgrep",
  });
  await downloadFile(downloadUrl, localBin);

  if (process.platform !== "win32") {
    chmodSync(localBin, 0o755);
  }

  emitOutputNotice({
    level: "success",
    message: "Installed opengrep",
    detail: localBin,
    source: "semgrep",
  });
  return localBin;
}
