#!/usr/bin/env node
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";

const baseUrl = process.env.JUICE_SHOP_URL ?? "http://127.0.0.1:3000";
const outputPath = requiredEnv("RUNTIME_PROBE_OUTPUT");
const findingsPath = requiredEnv("RUNTIME_PROBE_FINDINGS");

const findings = [];
const results = [];

await runLoginRegression();
await runTypeConfusion();
await runSearchMutations();
await assertHealthy("final-health");

writeFileSync(
  outputPath,
  `${JSON.stringify(
    {
      schemaVersion: 1,
      target: baseUrl,
      caseCount: results.length,
      anomalyCount: findings.length,
      cases: results,
    },
    null,
    2,
  )}\n`,
);
writeFileSync(
  findingsPath,
  findings.map((finding) => JSON.stringify(finding)).join("\n") + (findings.length ? "\n" : ""),
);
console.log(JSON.stringify({ ok: true, cases: results.length, anomalies: findings.length }));

async function runLoginRegression() {
  const cases = [
    {
      name: "admin-valid",
      body: { email: "admin@juice-sh.op", password: "admin123" },
      expectAuthenticated: true,
    },
    {
      name: "jim-valid",
      body: { email: "jim@juice-sh.op", password: "ncc-1701" },
      expectAuthenticated: true,
    },
    {
      name: "bender-valid",
      body: { email: "bender@juice-sh.op", password: "OhG0dPlease1nsertLiquor!" },
      expectAuthenticated: true,
    },
    ...[
      "admin@juice-sh.op'-- ",
      "jim@juice-sh.op'-- ",
      "bender@juice-sh.op'-- ",
      "chris.pike@juice-sh.op'-- ",
      "' OR 1=1-- ",
      '" OR "1"="1',
      "admin@juice-sh.op'/**/OR/**/1=1-- ",
      "admin@juice-sh.op%27-- ",
    ].map((email, index) => ({
      name: `login-injection-${String(index + 1).padStart(2, "0")}`,
      body: { email, password: "definitely-not-the-password" },
      expectAuthenticated: false,
    })),
  ];

  for (const testCase of cases) {
    const response = await jsonRequest("POST", "/rest/user/login", testCase.body);
    const authenticated = Boolean(response.json?.authentication?.token);
    const passed = testCase.expectAuthenticated
      ? response.status === 200 && authenticated
      : !authenticated && response.status !== 200;
    record({
      group: "login-regression",
      name: testCase.name,
      requestDigest: digest(JSON.stringify(testCase.body)),
      status: response.status,
      authenticated,
      passed,
      durationMs: response.durationMs,
      responseDigest: response.bodyDigest,
    });
    if (!passed) {
      addFinding({
        file: "runtime/rest-user-login",
        title: testCase.expectAuthenticated
          ? "Legitimate login regression"
          : "Injection-shaped login bypass",
        severity: testCase.expectAuthenticated ? "high" : "critical",
        cwe: testCase.expectAuthenticated ? "CWE-287" : "CWE-89",
      });
    }
  }
}

async function runTypeConfusion() {
  const bodies = [
    { email: null, password: "x" },
    { email: [], password: "x" },
    { email: {}, password: "x" },
    { email: "admin@juice-sh.op", password: null },
    { email: "admin@juice-sh.op", password: [] },
    { email: "admin@juice-sh.op", password: {} },
    { email: 7, password: true },
    { email: "A".repeat(2048), password: "B".repeat(2048) },
  ];
  for (const [index, body] of bodies.entries()) {
    const response = await jsonRequest("POST", "/rest/user/login", body);
    const authenticated = Boolean(response.json?.authentication?.token);
    const passed = !authenticated && response.status < 500;
    record({
      group: "login-type-confusion",
      name: `type-confusion-${String(index + 1).padStart(2, "0")}`,
      requestDigest: digest(JSON.stringify(body)),
      status: response.status,
      authenticated,
      passed,
      durationMs: response.durationMs,
      responseDigest: response.bodyDigest,
    });
    if (!passed) {
      addFinding({
        file: "runtime/rest-user-login",
        title: authenticated
          ? "Type-confused login input authenticated"
          : "Type-confused login input caused server error",
        severity: authenticated ? "critical" : "medium",
        cwe: "CWE-20",
      });
    }
  }
}

async function runSearchMutations() {
  const payloads = [
    "normal",
    "'",
    '"',
    "%' OR 1=1--",
    "../".repeat(32),
    "${7*7}",
    "<canary data-x='1'>",
    "(?:a+)+$",
    "💥".repeat(128),
    "A".repeat(2048),
  ];
  for (const [index, payload] of payloads.entries()) {
    const response = await rawRequest(
      "GET",
      `/rest/products/search?q=${encodeURIComponent(payload)}`,
    );
    const passed = response.status < 500 && response.error === undefined;
    record({
      group: "product-search-mutations",
      name: `search-${String(index + 1).padStart(2, "0")}`,
      requestDigest: digest(payload),
      status: response.status,
      passed,
      durationMs: response.durationMs,
      responseDigest: response.bodyDigest,
      error: response.error,
    });
    if (!passed) {
      addFinding({
        file: "runtime/rest-products-search",
        title: "Bounded search mutation caused server failure",
        severity: "medium",
        cwe: "CWE-20",
      });
    }
  }
}

async function assertHealthy(name) {
  const response = await rawRequest("GET", "/");
  const passed = response.status >= 200 && response.status < 500 && response.error === undefined;
  record({
    group: "health",
    name,
    status: response.status,
    passed,
    durationMs: response.durationMs,
    responseDigest: response.bodyDigest,
    error: response.error,
  });
  if (!passed) {
    addFinding({
      file: "runtime/application-health",
      title: "Application became unhealthy during bounded probes",
      severity: "high",
      cwe: "CWE-400",
    });
  }
}

async function jsonRequest(method, route, body) {
  const response = await rawRequest(method, route, {
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  let json;
  try {
    json = JSON.parse(response.bodyText ?? "");
  } catch {
    json = undefined;
  }
  return { ...response, json };
}

async function rawRequest(method, route, init = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8_000);
  const started = performance.now();
  try {
    const response = await fetch(new URL(route, baseUrl), {
      method,
      redirect: "manual",
      signal: controller.signal,
      ...init,
    });
    const bodyText = (await response.text()).slice(0, 1_000_000);
    return {
      status: response.status,
      durationMs: Math.round(performance.now() - started),
      bodyText,
      bodyDigest: digest(bodyText),
    };
  } catch (error) {
    return {
      status: null,
      durationMs: Math.round(performance.now() - started),
      error: error?.name ?? String(error),
      bodyDigest: null,
    };
  } finally {
    clearTimeout(timer);
  }
}

function record(row) {
  results.push(row);
  console.log(JSON.stringify(row));
}

function addFinding({ file, title, severity, cwe }) {
  const key = `${file}\u0000${title}\u0000${cwe}`;
  if (findings.some((finding) => finding._key === key)) return;
  findings.push({
    _key: key,
    file,
    line: 1,
    title,
    severity,
    class: "isolated-runtime-probe",
    cwe,
  });
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

process.on("exit", () => {
  for (const finding of findings) delete finding._key;
});
