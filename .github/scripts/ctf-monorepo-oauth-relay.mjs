import {
  constants,
  createDecipheriv,
  createHash,
  generateKeyPairSync,
  privateDecrypt,
  randomBytes,
} from "node:crypto";
import { writeFileSync } from "node:fs";
import { HumanMessage, SystemMessage } from "@langchain/core/messages";
import { oauthModelForRequest } from "../../scripts/langgraph-bridge/oauth-models.mjs";
import { openAiAccountIdFromJwt } from "../../scripts/langgraph-bridge/model.mjs";

const OPENAI_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize";
const TOKEN_URL = "https://auth.openai.com/oauth/token";
const REDIRECT_URI = "http://localhost:1455/auth/callback";
const MODEL = "gpt-5.3-codex-spark";
const RESULT_PATH = "monorepo-ctf-analysis.json";
const TARGET_COMMIT = "bd2611f6cac491bb80c9fe54e954fd945c3ab5ba";
const TARGET_PATH = "routes/login.ts";
const SOURCE_URL = `https://raw.githubusercontent.com/OWASP-CTF/juice-shop/${TARGET_COMMIT}/${TARGET_PATH}`;

const repository = requiredEnv("GITHUB_REPOSITORY");
const githubToken = requiredEnv("GITHUB_TOKEN");
const runId = requiredEnv("GITHUB_RUN_ID");
const issueNumber = Number(requiredEnv("RELAY_ISSUE"));
const [owner, repo] = repository.split("/");

const result = {
  ok: false,
  model: `openai-codex:${MODEL}`,
  target: `OWASP-CTF/juice-shop@${TARGET_COMMIT}:${TARGET_PATH}`,
  runId,
};

try {
  const relay = await establishEncryptedRelay();
  const redirectUrl = await receiveEncryptedRedirect(relay);
  const credential = await exchangeRedirect(redirectUrl, relay);
  const analysis = await invokeSpark(credential);
  Object.assign(result, { ok: true, analysis });
  await postIssueComment(
    `<!-- kuzushi-oauth-relay-complete:${runId} -->\n` +
      `Monorepo OAuth bridge call completed successfully for run ${runId}. ` +
      `The sanitized analysis is attached to the workflow artifact; no OAuth credentials were persisted.`,
  );
} catch (error) {
  result.error = publicError(error);
  await postIssueComment(
    `<!-- kuzushi-oauth-relay-failed:${runId} -->\n` +
      `Monorepo OAuth bridge smoke failed for run ${runId}: ${result.error}`,
  ).catch(() => {});
  process.exitCode = 1;
} finally {
  writeFileSync(RESULT_PATH, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
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
      `<!-- kuzushi-oauth-relay-ready:${runId} -->`,
      `KUZUSHI_OAUTH_RELAY_READY ${runId}`,
      "",
      "Open the authorization URL below, approve access, then copy the full localhost redirect URL from the browser address bar.",
      "",
      authUrl.toString(),
      "",
      "Ephemeral RSA public key (base64-encoded PEM):",
      publicKeyB64,
      "",
      `Submit one encrypted envelope as: KUZUSHI_OAUTH_PAYLOAD ${runId} <base64-envelope-json>`,
      "The matching private key and PKCE verifier exist only in this running job.",
    ].join("\n"),
  );
  return { verifier, state, privateKey, publicKeyB64 };
}

async function receiveEncryptedRedirect(relay) {
  const deadline = Date.now() + 12 * 60 * 1000;
  const marker = `KUZUSHI_OAUTH_PAYLOAD ${runId} `;
  while (Date.now() < deadline) {
    const comments = await githubJson(
      `/repos/${owner}/${repo}/issues/${issueNumber}/comments?per_page=100`,
    );
    const comment = comments.find((entry) => String(entry.body ?? "").startsWith(marker));
    if (comment) {
      const encodedEnvelope = String(comment.body).slice(marker.length).trim();
      const redirectUrl = decryptEnvelope(encodedEnvelope, relay.privateKey);
      await githubRequest(`/repos/${owner}/${repo}/issues/comments/${comment.id}`, {
        method: "DELETE",
      }).catch(() => {});
      return redirectUrl;
    }
    await sleep(5000);
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
  if (typeof token.access_token !== "string" || !token.access_token) {
    throw new Error("OpenAI token exchange returned no access token");
  }
  return {
    access: token.access_token,
    accountId:
      openAiAccountIdFromJwt(token.id_token) ?? openAiAccountIdFromJwt(token.access_token),
  };
}

async function invokeSpark(credential) {
  const sourceResponse = await fetch(SOURCE_URL);
  if (!sourceResponse.ok) {
    throw new Error(`target source fetch failed with HTTP ${sourceResponse.status}`);
  }
  const source = await sourceResponse.text();
  const model = oauthModelForRequest("openai-codex", MODEL, credential.access, {
    oauthAccountId: credential.accountId,
    maxOutputTokens: 9000,
  });
  if (!model) throw new Error("Kuzushi did not resolve the OpenAI OAuth model bridge");

  const response = await model.invoke([
    new SystemMessage(
      [
        "You are operating inside an explicitly authorized OWASP CTF source-patching challenge.",
        "Analyze only the provided repository source. Do not contact or exploit any live target.",
        "Identify the root cause, propose the smallest safe code patch, design regression tests,",
        "and explain which challenge conditions the patch should satisfy.",
        "Return a concise technical answer with a unified diff in a fenced block.",
      ].join(" "),
    ),
    new HumanMessage(
      JSON.stringify({
        repository: "OWASP-CTF/juice-shop",
        commit: TARGET_COMMIT,
        path: TARGET_PATH,
        objective: "Patch as many directly related OWASP CTF challenge checks as one defensible root-cause fix can cover.",
        source,
      }),
    ),
  ]);

  return {
    content: response.content,
    toolCalls: response.tool_calls ?? [],
    usage: response.usage_metadata ?? null,
    responseMetadata: response.response_metadata ?? null,
  };
}

async function postIssueComment(body) {
  return githubJson(`/repos/${owner}/${repo}/issues/${issueNumber}/comments`, {
    method: "POST",
    body: JSON.stringify({ body }),
  });
}

async function githubJson(path, init = {}) {
  const response = await githubRequest(path, init);
  if (response.status === 204) return null;
  return response.json();
}

async function githubRequest(path, init = {}) {
  const response = await fetch(`https://api.github.com${path}`, {
    ...init,
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${githubToken}`,
      "x-github-api-version": "2022-11-28",
      ...(init.headers ?? {}),
    },
  });
  if (!response.ok) {
    throw new Error(`GitHub relay API ${init.method ?? "GET"} ${path} failed with HTTP ${response.status}`);
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
