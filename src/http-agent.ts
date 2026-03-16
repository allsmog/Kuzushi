/**
 * Connection pooling & HTTP agent reuse.
 *
 * Provides cached `http.Agent` / `https.Agent` instances with `keepAlive`
 * enabled and configurable `maxSockets` (via `KUZUSHI_HTTP_CONNECTIONS` env
 * var, default 10).  Also installs a global `undici` dispatcher so that all
 * `fetch()` calls (including those made by `@mariozechner/pi-ai` and the
 * Anthropic SDK) share a connection pool.
 *
 * Proxy support: when `HTTP_PROXY` or `HTTPS_PROXY` is set, the HTTPS agent
 * is replaced with one from `https-proxy-agent` (already a transitive
 * dependency via `pi-ai -> proxy-agent`).
 */

import http from "node:http";
import https from "node:https";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// Minimal type surface for the parts of undici we touch at runtime.
// We load undici dynamically via require() because it ships with Node 22+
// but is not listed as a direct dependency.
// ---------------------------------------------------------------------------

interface UndiciDispatcher {
  close(): Promise<void>;
  destroy(): Promise<void>;
}

interface UndiciModule {
  Agent: new (opts?: {
    connections?: number;
    keepAliveTimeout?: number;
    pipelining?: number;
  }) => UndiciDispatcher;
  ProxyAgent: (new (opts?: {
    uri?: string;
    connections?: number;
    keepAliveTimeout?: number;
  }) => UndiciDispatcher) | undefined;
  setGlobalDispatcher(dispatcher: UndiciDispatcher): void;
  getGlobalDispatcher(): UndiciDispatcher;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Resolve proxy URL from env vars, checking both upper and lowercase variants. */
function resolveProxyUrl(): string | undefined {
  return process.env["HTTPS_PROXY"] ?? process.env["https_proxy"] ?? process.env["HTTP_PROXY"] ?? process.env["http_proxy"];
}

function resolveMaxSockets(): number {
  const raw = process.env["KUZUSHI_HTTP_CONNECTIONS"];
  if (raw == null) return 10;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 1 ? Math.floor(parsed) : 10;
}

// ---------------------------------------------------------------------------
// Cached agents (lazy singletons)
// ---------------------------------------------------------------------------

let cachedHttpAgent: http.Agent | undefined;
let cachedHttpsAgent: https.Agent | undefined;
let globalDispatcherInstalled = false;

/**
 * Return a cached `http.Agent` with keepAlive enabled.
 */
export function getHttpAgent(): http.Agent {
  if (!cachedHttpAgent) {
    cachedHttpAgent = new http.Agent({
      keepAlive: true,
      maxSockets: resolveMaxSockets(),
      // 30 s free-socket timeout to avoid holding connections too long
      timeout: 30_000,
    });
  }
  return cachedHttpAgent;
}

/**
 * Return a cached `https.Agent` with keepAlive enabled.
 *
 * When `HTTPS_PROXY` or `HTTP_PROXY` is set, this falls back to
 * `https-proxy-agent` if available; otherwise it returns a standard
 * `https.Agent`.
 */
export function getHttpsAgent(): https.Agent {
  if (!cachedHttpsAgent) {
    const proxyUrl = resolveProxyUrl();
    if (proxyUrl) {
      cachedHttpsAgent = createProxyAgent(proxyUrl);
    } else {
      cachedHttpsAgent = new https.Agent({
        keepAlive: true,
        maxSockets: resolveMaxSockets(),
        timeout: 30_000,
      });
    }
  }
  return cachedHttpsAgent;
}

/**
 * Install a global undici `Agent` as the default dispatcher for `fetch()`.
 *
 * This is safe to call multiple times; only the first call has an effect.
 * Node 22+ exposes undici internals; on older runtimes this is a no-op.
 */
export function installGlobalDispatcher(): void {
  if (globalDispatcherInstalled) return;
  globalDispatcherInstalled = true;

  try {
    // Node 22+ bundles undici and exposes setGlobalDispatcher / Agent.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const undici = require("undici") as UndiciModule;
    const maxConnections = resolveMaxSockets();

    const proxyUrl = resolveProxyUrl();
    const ProxyAgentCtor = undici.ProxyAgent;
    if (proxyUrl && typeof ProxyAgentCtor === "function") {
      const dispatcher = new ProxyAgentCtor({
        uri: proxyUrl,
        connections: maxConnections,
        keepAliveTimeout: 30_000,
      });
      undici.setGlobalDispatcher(dispatcher);
    } else {
      const dispatcher = new undici.Agent({
        connections: maxConnections,
        keepAliveTimeout: 30_000,
        pipelining: 1,
      });
      undici.setGlobalDispatcher(dispatcher);
    }
  } catch {
    // undici not available (should not happen on Node 22+). Silently skip.
  }
}

/**
 * Destroy cached agents and close the global dispatcher.
 * Call once at process exit for graceful cleanup.
 */
export function cleanup(): void {
  if (cachedHttpAgent) {
    cachedHttpAgent.destroy();
    cachedHttpAgent = undefined;
  }
  if (cachedHttpsAgent) {
    cachedHttpsAgent.destroy();
    cachedHttpsAgent = undefined;
  }

  // Close the global undici dispatcher if we installed one.
  if (globalDispatcherInstalled) {
    try {
      const undici = require("undici") as UndiciModule;
      const dispatcher = undici.getGlobalDispatcher();
      if (dispatcher && typeof dispatcher.close === "function") {
        // close() returns a promise but we are in an exit handler, so fire
        // and forget. destroy() is synchronous in practice.
        dispatcher.close().catch(() => {});
      }
    } catch {
      // Best-effort.
    }
    globalDispatcherInstalled = false;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Attempt to create an HTTPS proxy agent via `https-proxy-agent`.
 * Falls back to a standard `https.Agent` if the package is unavailable.
 */
function createProxyAgent(proxyUrl: string): https.Agent {
  try {
    // `https-proxy-agent` is a transitive dep of `pi-ai` via `proxy-agent`.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { HttpsProxyAgent } = require("https-proxy-agent") as {
      HttpsProxyAgent: new (proxy: string, opts?: Record<string, unknown>) => https.Agent;
    };
    return new HttpsProxyAgent(proxyUrl, {
      keepAlive: true,
      maxSockets: resolveMaxSockets(),
    });
  } catch {
    // Package not resolvable — warn and fall back to direct connection.
    console.warn("[kuzushi] HTTPS_PROXY is set but https-proxy-agent could not be loaded. Falling back to direct connection.");
    return new https.Agent({
      keepAlive: true,
      maxSockets: resolveMaxSockets(),
      timeout: 30_000,
    });
  }
}
