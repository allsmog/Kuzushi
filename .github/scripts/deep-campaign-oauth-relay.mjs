import {
  constants,
  createDecipheriv,
  createHash,
  generateKeyPairSync,
  privateDecrypt,
  randomBytes,
} from "node:crypto";
import { chmodSync, mkdirSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";

const OPENAI_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize";
const TOKEN_URL = "https://auth.openai.com/oauth/token";
const REDIRECT_URI = "http://localhost:1455/auth/callback";
const POLL_INTERVAL_MS = 5_000;
const RELAY_DEADLINE_MS = 20 * 60 * 1_000;

const repository = requiredEnv("GITHUB_REPOSITORY");
const githubToken = requiredEnv("GITHUB_TOKEN");
const runId = requiredEnv("GITHUB_RUN_ID");
const issueNumber = Number(requiredEnv("RELAY_ISSUE"));
const credentialsPath = requiredEnv("KUZUSHI_OAUTH_CREDENTIALS");
const [owner, repo] = repository.split("/");

try {
  const relay = await establishEncryptedRelay();
  const redirectUrl = await receiveEncryptedRedirect(relay.privateKey);
  const credential = await exchangeRedirect(redirectUrl, relay);
  writeCredentialBag(credential);
  await postIssueComment(
    `<!-- kuzushi-deep-campaign-oauth-ready:${runId} -->\n` +
      `Encrypted callback consumed for run ${runId}. The temporary credential exists only in the running job.`,
  );
} catch (error) {
  const message = publicError(error);
  await postIssueComment(
    `<!-- kuzushi-deep-campaign-oauth-failed:${runId} -->\n` +
      `Deep campaign OAuth relay failed for run ${runId}: ${message}`,
  ).catch(() => {});
  throw error;
}

async function establishEncryptedRelay() {
  const verifier = base64url(randomBytes(64));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  const state = base64url(randomBytes(32));
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 3072,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const authUrl = new URL(AUTHORIZE_URL);
  authUrl.searchParams.set("client_id", OPENAI_CLIENT_ID);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("scope", "openid profile email offline_access");
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("state", state);

  const publicKeyB64 = Buffer.from(publicKey, "utf8").toString("base64");
  await postIssueComment(
    [
      `<!-- kuzushi-deep-campaign-oauth:${runId} -->`,
      `KUZUSHI_DEEP_CAMPAIGN_OAUTH_READY ${runId}`,
      "",
      "Open the authorization URL below, approve access, then copy the full localhost redirect URL from the browser address bar.",
      "",
      authUrl.toString(),
      "",
      "Ephemeral RSA public key (base64-encoded PEM):",
      publicKeyB64,
      "",
      `Submit one encrypted envelope as: KUZUSHI_DEEP_CAMPAIGN_OAUTH_PAYLOAD ${runId} <base64-envelope-json>`,
      "The matching private key and PKCE verifier exist only in this running job.",
    ].join("\n"),
  );
  return { verifier, state, privateKey };
}

async function receiveEncryptedRedirect(privateKey) {
  const deadline = Date.now() + RELAY_DEADLINE_MS;
  const marker = `KUZUSHI_DEEP_CAMPAIGN_OAUTH_PAYLOAD ${runId} `;
  while (Date.now() < deadline) {
    const comments = await githubJson(
      `/repos/${owner}/${repo}/issues/${issueNumber}/comments?per_page=100`,
    );
    const comment = comments.find((entry) => String(entry.body ?? "").startsWith(marker));
    if (comment) {
      const encodedEnvelope = String(comment.body).slice(marker.length).trim();
      const redirectUrl = decryptEnvelope(encodedEnvelope, privateKey);
      await githubRequest(`/repos/${owner}/${repo}/issues/comments/${comment.id}`, {
        method: "DELETE",
      }).catch(() => {});
      return redirectUrl;
    }
    await sleep(POLL_INTERVAL_MS);
  }
  throw new Error("authorization payload was not received before the relay deadline");
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
  const payload = JSON.parse(plaintext);
  if (typeof payload.redirectUrl !== "string" || !payload.redirectUrl.trim()) {
    throw new Error("encrypted relay payload did not contain redirectUrl");
  }
  return payload.redirectUrl.trim();
}

async function exchangeRedirect(redirectUrl, relay) {
  const parsed = new URL(redirectUrl);
  const code = parsed.searchParams.get("code");
  const returnedState = parsed.searchParams.get("state");
  if (!code) throw new Error("authorization redirect did not contain a code");
  if (returnedState !== relay.state) throw new Error("authorization state mismatch");

  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: OPENAI_CLIENT_ID,
      code_verifier: relay.verifier,
    }).toString(),
  });
  if (!response.ok) {
    throw new Error(`OpenAI token exchange failed with HTTP ${response.status}`);
  }
  const token = await response.json();
  const access = nonEmpty(token.access_token);
  if (!access) throw new Error("OpenAI token exchange returned no access token");
  const accountId = accountIdFromJwt(token.id_token) ?? accountIdFromJwt(access);
  return {
    access,
    refresh: nonEmpty(token.refresh_token),
    expires: Date.now() + Math.max(1, Number(token.expires_in ?? 3600)) * 1000,
    ...(accountId ? { accountId } : {}),
  };
}

function writeCredentialBag(credential) {
  mkdirSync(path.dirname(credentialsPath), { recursive: true, mode: 0o700 });
  const tmp = `${credentialsPath}.tmp.${process.pid}`;
  writeFileSync(tmp, `${JSON.stringify({ "openai-codex": credential }, null, 2)}\n`, {
    mode: 0o600,
  });
  chmodSync(tmp, 0o600);
  renameSync(tmp, credentialsPath);
  chmodSync(credentialsPath, 0o600);
}

function accountIdFromJwt(token) {
  if (!nonEmpty(token)) return undefined;
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return (
      nonEmpty(claims.chatgpt_account_id) ??
      nonEmpty(claims["https://api.openai.com/auth"]?.chatgpt_account_id) ??
      nonEmpty(claims.organizations?.[0]?.id)
    );
  } catch {
    return undefined;
  }
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

function nonEmpty(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function base64url(buffer) {
  return buffer.toString("base64url");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
