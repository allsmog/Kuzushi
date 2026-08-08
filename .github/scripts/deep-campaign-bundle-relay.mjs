import {
  constants,
  createDecipheriv,
  createHash,
  generateKeyPairSync,
  privateDecrypt,
  randomBytes,
} from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const POLL_INTERVAL_MS = 5_000;
const RELAY_DEADLINE_MS = 20 * 60 * 1_000;
const MAX_AFE_ZIP_BYTES = 32 * 1024 * 1024;
const MAX_OXIDIZED_ZIP_BYTES = 256 * 1024 * 1024;

const repository = requiredEnv("GITHUB_REPOSITORY");
const githubToken = requiredEnv("GITHUB_TOKEN");
const runId = requiredEnv("GITHUB_RUN_ID");
const issueNumber = Number(requiredEnv("RELAY_ISSUE"));
const campaignRoot = requiredEnv("CAMPAIGN_ROOT");
const afeDir = requiredEnv("AFE_DIR");
const oxidizedDir = requiredEnv("OXIDIZED_DIR");
const oxidizedPinnedDir = requiredEnv("OXIDIZED_PINNED_DIR");
const afeSha = requiredEnv("AFE_SHA");
const oxidizedSha = requiredEnv("OXIDIZED_SHA");
const oxidizedPinnedSha = requiredEnv("OXIDIZED_PINNED_SHA");
const reportDir = requiredEnv("REPORT_DIR");
const [owner, repo] = repository.split("/");

const relayRoot = path.join(campaignRoot, `.source-relay-${runId}`);

try {
  const relay = await establishEncryptedRelay();
  const payload = await receiveEncryptedPayload(relay);
  validatePayload(payload, relay.nonce);
  mkdirSync(relayRoot, { recursive: true, mode: 0o700 });

  const afeReceipt = await consumeArtifact({
    label: "agentic-fuzz-engine",
    url: payload.afeUrl,
    expectedZipDigest: payload.afeDigest,
    maxBytes: MAX_AFE_ZIP_BYTES,
    validate: validateAfeBundle,
    install: installAfeBundle,
  });
  const oxidizedReceipt = await consumeArtifact({
    label: "oxidized-joern",
    url: payload.oxidizedUrl,
    expectedZipDigest: payload.oxidizedDigest,
    maxBytes: MAX_OXIDIZED_ZIP_BYTES,
    validate: validateOxidizedBundle,
    install: installOxidizedBundle,
  });

  mkdirSync(path.join(reportDir, "provenance"), { recursive: true, mode: 0o700 });
  writeFileSync(
    path.join(reportDir, "provenance", "private-source-relay.json"),
    `${JSON.stringify({
      schemaVersion: 1,
      runId,
      agenticFuzzEngine: afeReceipt,
      oxidizedJoern: oxidizedReceipt,
      oauthOrDownloadUrlsPersisted: false,
    }, null, 2)}\n`,
    { mode: 0o600 },
  );

  await postIssueComment(
    `<!-- kuzushi-deep-campaign-bundles-consumed:${runId} -->\n` +
      `Encrypted source bundles were consumed and verified for run ${runId}. ` +
      `No private artifact URL was persisted.`,
  );
} catch (error) {
  const message = publicError(error);
  await postIssueComment(
    `<!-- kuzushi-deep-campaign-bundles-failed:${runId} -->\n` +
      `Deep campaign source-bundle relay failed for run ${runId}: ${message}`,
  ).catch(() => {});
  throw error;
} finally {
  rmSync(relayRoot, { recursive: true, force: true });
}

async function establishEncryptedRelay() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 3072,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const nonce = base64url(randomBytes(32));
  const publicKeyB64 = Buffer.from(publicKey, "utf8").toString("base64");
  await postIssueComment(
    [
      `<!-- kuzushi-deep-campaign-bundles:${runId} -->`,
      `KUZUSHI_DEEP_CAMPAIGN_BUNDLE_RELAY_READY ${runId}`,
      `Nonce: ${nonce}`,
      "",
      "Ephemeral RSA public key (base64-encoded PEM):",
      publicKeyB64,
      "",
      `Submit one encrypted envelope as: KUZUSHI_DEEP_CAMPAIGN_BUNDLE_PAYLOAD ${runId} <base64-envelope-json>`,
      "The matching private key exists only in this running job. Private artifact URLs must appear only inside the encrypted payload.",
    ].join("\n"),
  );
  return { privateKey, nonce };
}

async function receiveEncryptedPayload(relay) {
  const deadline = Date.now() + RELAY_DEADLINE_MS;
  const marker = `KUZUSHI_DEEP_CAMPAIGN_BUNDLE_PAYLOAD ${runId} `;
  while (Date.now() < deadline) {
    const comments = await githubJson(
      `/repos/${owner}/${repo}/issues/${issueNumber}/comments?per_page=100`,
    );
    const comment = comments.find((entry) => String(entry.body ?? "").startsWith(marker));
    if (comment) {
      const encodedEnvelope = String(comment.body).slice(marker.length).trim();
      let payload;
      try {
        payload = decryptEnvelope(encodedEnvelope, relay.privateKey);
      } finally {
        await githubRequest(`/repos/${owner}/${repo}/issues/comments/${comment.id}`, {
          method: "DELETE",
        }).catch(() => {});
      }
      return payload;
    }
    await sleep(POLL_INTERVAL_MS);
  }
  throw new Error("source-bundle payload was not received before the relay deadline");
}

function decryptEnvelope(encodedEnvelope, privateKey) {
  const envelope = JSON.parse(Buffer.from(encodedEnvelope, "base64").toString("utf8"));
  const aesKey = privateDecrypt(
    {
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(envelope.encryptedKey, "base64"),
  );
  const decipher = createDecipheriv(
    "aes-256-gcm",
    aesKey,
    Buffer.from(envelope.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
  return JSON.parse(plaintext);
}

function validatePayload(payload, nonce) {
  if (!payload || typeof payload !== "object") throw new Error("bundle payload is not an object");
  if (payload.nonce !== nonce) throw new Error("bundle relay nonce mismatch");
  validateSignedUrl(payload.afeUrl, "afeUrl");
  validateSignedUrl(payload.oxidizedUrl, "oxidizedUrl");
  validateDigest(payload.afeDigest, "afeDigest");
  validateDigest(payload.oxidizedDigest, "oxidizedDigest");
}

function validateSignedUrl(raw, label) {
  if (typeof raw !== "string" || !raw.trim()) throw new Error(`${label} is missing`);
  const url = new URL(raw);
  if (url.protocol !== "https:" || !url.hostname.endsWith(".oaiusercontent.com")) {
    throw new Error(`${label} must be a signed oaiusercontent.com HTTPS URL`);
  }
}

function validateDigest(raw, label) {
  if (typeof raw !== "string" || !/^sha256:[0-9a-f]{64}$/i.test(raw)) {
    throw new Error(`${label} must use sha256:<64 hex>`);
  }
}

async function consumeArtifact({ label, url, expectedZipDigest, maxBytes, validate, install }) {
  const work = path.join(relayRoot, label);
  const zipPath = path.join(work, `${label}.zip`);
  const unzipDir = path.join(work, "zip");
  const extractDir = path.join(work, "bundle");
  mkdirSync(unzipDir, { recursive: true, mode: 0o700 });
  mkdirSync(extractDir, { recursive: true, mode: 0o700 });

  const zipBytes = await downloadBounded(url, maxBytes);
  const zipDigest = `sha256:${createHash("sha256").update(zipBytes).digest("hex")}`;
  if (zipDigest.toLowerCase() !== expectedZipDigest.toLowerCase()) {
    throw new Error(`${label} ZIP digest mismatch`);
  }
  writeFileSync(zipPath, zipBytes, { mode: 0o600 });

  const zipEntries = commandLines("unzip", ["-Z1", zipPath]);
  ensureArchivePaths(zipEntries, `${label} ZIP`);
  run("unzip", ["-q", zipPath, "-d", unzipDir]);
  const tarFiles = zipEntries
    .map((entry) => path.join(unzipDir, entry))
    .filter((entry) => entry.endsWith(".tar.gz") && existsSync(entry));
  if (tarFiles.length !== 1) throw new Error(`${label} ZIP must contain exactly one .tar.gz`);
  const checksumFiles = zipEntries
    .map((entry) => path.join(unzipDir, entry))
    .filter((entry) => entry.endsWith(".tar.gz.sha256") && existsSync(entry));
  if (checksumFiles.length !== 1) throw new Error(`${label} ZIP must contain exactly one checksum`);

  const tarDigest = createHash("sha256").update(readFileSync(tarFiles[0])).digest("hex");
  const declaredTarDigest = readFileSync(checksumFiles[0], "utf8").trim().split(/\s+/)[0];
  if (!/^[0-9a-f]{64}$/i.test(declaredTarDigest) || tarDigest !== declaredTarDigest.toLowerCase()) {
    throw new Error(`${label} internal tar checksum mismatch`);
  }

  const tarEntries = commandLines("tar", ["-tzf", tarFiles[0]]);
  ensureArchivePaths(tarEntries, `${label} tar`);
  run("tar", ["-xzf", tarFiles[0], "-C", extractDir]);
  const receipt = validate(extractDir);
  install(extractDir);
  return {
    repository: receipt.repository,
    requestedSha: receipt.requestedSha,
    additionalSha: receipt.additionalSha ?? null,
    zipDigest,
    tarDigest: `sha256:${tarDigest}`,
  };
}

async function downloadBounded(rawUrl, maxBytes) {
  const response = await fetch(rawUrl, { redirect: "follow" });
  if (!response.ok) throw new Error(`source bundle download failed with HTTP ${response.status}`);
  const length = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(length) && length > maxBytes) throw new Error("source bundle exceeds size limit");
  const reader = response.body?.getReader();
  if (!reader) throw new Error("source bundle response had no body");
  const chunks = [];
  let total = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("source bundle exceeded streamed size limit");
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total);
}

function validateAfeBundle(root) {
  const manifest = readManifest(root);
  if (manifest.repository !== "allsmog/agentic-fuzz-engine" || manifest.sha !== afeSha) {
    throw new Error("Agentic Fuzz Engine manifest provenance mismatch");
  }
  const source = path.join(root, manifest.sourcePath ?? "source");
  verifyGitCommit(source, afeSha, "Agentic Fuzz Engine");
  return { repository: manifest.repository, requestedSha: afeSha };
}

function validateOxidizedBundle(root) {
  const manifest = readManifest(root);
  if (manifest.repository !== "allsmog/oxidized-joern") {
    throw new Error("Oxidized Joern manifest repository mismatch");
  }
  const latest = path.join(root, manifest.latest?.sourcePath ?? "latest");
  const pinned = path.join(root, manifest.pinned?.sourcePath ?? "pinned");
  if (manifest.latest?.sha !== oxidizedSha || manifest.pinned?.sha !== oxidizedPinnedSha) {
    throw new Error("Oxidized Joern manifest commit mismatch");
  }
  verifyGitCommit(latest, oxidizedSha, "Oxidized Joern latest");
  verifyGitCommit(pinned, oxidizedPinnedSha, "Oxidized Joern pinned");
  return {
    repository: manifest.repository,
    requestedSha: oxidizedSha,
    additionalSha: oxidizedPinnedSha,
  };
}

function installAfeBundle(root) {
  installDirectory(path.join(root, "source"), afeDir);
}

function installOxidizedBundle(root) {
  const destinationRoot = path.dirname(oxidizedDir);
  if (path.dirname(oxidizedPinnedDir) !== destinationRoot) {
    throw new Error("Oxidized Joern destinations must share one parent");
  }
  rmSync(destinationRoot, { recursive: true, force: true });
  mkdirSync(destinationRoot, { recursive: true, mode: 0o700 });
  installDirectory(path.join(root, "latest"), oxidizedDir);
  installDirectory(path.join(root, "pinned"), oxidizedPinnedDir);
}

function installDirectory(source, destination) {
  rmSync(destination, { recursive: true, force: true });
  mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
  try {
    renameSync(source, destination);
  } catch {
    cpSync(source, destination, { recursive: true, errorOnExist: true, preserveTimestamps: true });
    rmSync(source, { recursive: true, force: true });
  }
}

function readManifest(root) {
  const manifestPath = path.join(root, "bundle-manifest.json");
  if (!existsSync(manifestPath)) throw new Error("bundle-manifest.json is missing");
  return JSON.parse(readFileSync(manifestPath, "utf8"));
}

function verifyGitCommit(directory, expected, label) {
  const result = spawnSync("git", ["-C", directory, "rev-parse", "HEAD"], {
    encoding: "utf8",
    timeout: 30_000,
  });
  if (result.status !== 0 || result.stdout.trim() !== expected) {
    throw new Error(`${label} extracted Git commit mismatch`);
  }
}

function ensureArchivePaths(entries, label) {
  if (!entries.length) throw new Error(`${label} is empty`);
  for (const entry of entries) {
    const normalized = String(entry).replaceAll("\\", "/");
    const segments = normalized.split("/").filter(Boolean);
    if (normalized.startsWith("/") || /^[A-Za-z]:\//.test(normalized) || segments.includes("..")) {
      throw new Error(`${label} contains an unsafe path`);
    }
  }
}

function commandLines(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 120_000 });
  if (result.status !== 0) throw new Error(`${command} inspection failed`);
  return result.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 300_000 });
  if (result.status !== 0) throw new Error(`${command} extraction failed`);
}

async function postIssueComment(body) {
  return githubJson(`/repos/${owner}/${repo}/issues/${issueNumber}/comments`, {
    method: "POST",
    body: JSON.stringify({ body }),
  });
}

async function githubJson(apiPath, init = {}) {
  const response = await githubRequest(apiPath, init);
  if (response.status === 204) return null;
  return response.json();
}

async function githubRequest(apiPath, init = {}) {
  const response = await fetch(`https://api.github.com${apiPath}`, {
    ...init,
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${githubToken}`,
      "x-github-api-version": "2022-11-28",
      ...(init.headers ?? {}),
    },
  });
  if (!response.ok) {
    throw new Error(`GitHub relay API ${init.method ?? "GET"} ${apiPath} failed with HTTP ${response.status}`);
  }
  return response;
}

function publicError(error) {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/[\r\n]+/g, " ").slice(0, 500);
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function base64url(buffer) {
  return buffer.toString("base64url");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
