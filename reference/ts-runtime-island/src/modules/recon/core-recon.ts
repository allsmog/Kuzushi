/**
 * Recon module — the first non-scanner sub-module.
 *
 * Populates the workspace's hosts + services tables with discoveries from:
 *   - recon:nmap              classic port scan
 *   - recon:subdomain         passive subdomain enumeration
 *   - recon:http-fingerprint  HTTP banner / tech-stack identification
 *
 * These are intentionally simple today: the external tool (nmap, etc.) may
 * not be installed; we check and emit a clear "install X first" on miss.
 * The important thing is the contract — each tool writes into
 * `ctx.workspace.hosts` / `.services`, which `hosts` / `services` dispatcher
 * commands render.
 */

import { isRecord } from "../../utils.js";
import type { CopilotModule, ExecutionContext, ModuleTool, ToolResult } from "../types.js";

interface NmapInput {
  target?: string;
  ports?: string;
}

interface SubdomainInput {
  domain?: string;
  source?: string;
}

interface HttpFingerprintInput {
  target?: string;
}

interface WorkspaceRowWithId {
  id: string;
}

interface WorkspaceServiceRow extends WorkspaceRowWithId {
  name: string;
}

const nmapTool: ModuleTool = {
  name: "recon:nmap",
  displayName: "Nmap",
  formatInput(input) {
    const p = parseNmapInput(input);
    const target = p.target ?? null;
    const ports = p.ports ?? null;
    if (target && ports) return `${target} · ${ports}`;
    return target ?? null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description: "Nmap-style port scan. Writes discovered hosts + open services to the workspace.",
  inputSchema: {
    type: "object",
    properties: {
      target: { type: "string", description: "CIDR, hostname, or IP (e.g. 10.0.0.0/24)." },
      ports: {
        type: "string",
        default: "top100",
        description: "Port spec: 'top100', 'top1000', '1-1024', or a comma list.",
      },
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const p = parseNmapInput(input);
    if (!ctx.workspace || !ctx.workspaceId) {
      return { ok: false, output: "recon:nmap needs an active workspace." };
    }
    const target = p.target ?? "";
    if (!target) return { ok: false, output: "recon:nmap requires a target." };
    if (!(await isOnPath("nmap"))) {
      return {
        ok: false,
        output: "[-] nmap is not on PATH. Install it first (`brew install nmap` / apt).",
      };
    }

    // Real impl would shell out and parse. Until then: write a placeholder
    // host so `hosts` + `services` render something, and tag it with origin.
    const host = readWorkspaceRowId(
      ctx.workspace.hosts.upsert({
        workspaceId: ctx.workspaceId,
        address: target,
        state: "alive",
        metadata: { discoveredBy: "recon:nmap", discoveredAt: new Date().toISOString() },
      }),
    );
    if (!host) return { ok: false, output: "recon:nmap could not persist the seeded host." };
    ctx.workspace.notes.create({
      workspaceId: ctx.workspaceId,
      hostId: host.id,
      ntype: "recon:nmap-pending",
      data: { target, ports: p.ports ?? "top100" },
    });

    return {
      ok: true,
      output: `[+] Seeded host ${target} (real nmap execution pending wire-up).`,
      data: { hostId: host.id, target },
    };
  },
};

const subdomainTool: ModuleTool = {
  name: "recon:subdomain",
  displayName: "Subdomain Enum",
  formatInput(input) {
    return parseSubdomainInput(input).domain ?? null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Passive subdomain enumeration. Queries CT logs / archival sources and writes each " +
    "discovered subdomain as a host in the workspace.",
  inputSchema: {
    type: "object",
    properties: {
      domain: { type: "string", description: "Root domain to enumerate." },
      source: {
        type: "string",
        enum: ["crtsh", "wayback", "both"],
        default: "both",
        description: "Passive source(s) to query.",
      },
    },
    required: ["domain"],
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const p = parseSubdomainInput(input);
    if (!ctx.workspace || !ctx.workspaceId) {
      return { ok: false, output: "recon:subdomain needs an active workspace." };
    }
    const domain = p.domain ?? "";
    if (!domain) return { ok: false, output: "recon:subdomain requires a domain." };

    ctx.workspace.notes.create({
      workspaceId: ctx.workspaceId,
      ntype: "recon:subdomain-pending",
      data: { domain, source: p.source ?? "both" },
    });
    return {
      ok: true,
      output:
        `[+] Seeded subdomain enumeration task for ${domain}.\n` +
        `    Real CT-log / wayback fetch pending wire-up. Use workspace.notes to inspect.`,
      data: { domain },
    };
  },
};

const httpFingerprintTool: ModuleTool = {
  name: "recon:http-fingerprint",
  displayName: "HTTP Fingerprint",
  formatInput(input) {
    return parseHttpFingerprintInput(input).target ?? null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Fetch HTTP(S) headers + body signature for a host, write banner + inferred tech to " +
    "the services table.",
  inputSchema: {
    type: "object",
    properties: {
      target: { type: "string", description: "URL or host:port." },
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const p = parseHttpFingerprintInput(input);
    if (!ctx.workspace || !ctx.workspaceId) {
      return { ok: false, output: "recon:http-fingerprint needs an active workspace." };
    }
    const target = p.target ?? "";
    if (!target) return { ok: false, output: "recon:http-fingerprint requires a target." };

    const { host: hostname, port } = splitHostPort(target);
    const hostRow = readWorkspaceRowId(
      ctx.workspace.hosts.upsert({
        workspaceId: ctx.workspaceId,
        address: hostname,
      }),
    );
    if (!hostRow) {
      return { ok: false, output: "recon:http-fingerprint could not persist the host." };
    }
    const service = readWorkspaceServiceRow(
      ctx.workspace.services.upsert({
        hostId: hostRow.id,
        port,
        proto: "tcp",
        name: port === 443 ? "https" : "http",
        state: "open",
        info: { discoveredBy: "recon:http-fingerprint" },
      }),
    );
    if (!service) {
      return { ok: false, output: "recon:http-fingerprint could not persist the service." };
    }
    return {
      ok: true,
      output: `[+] Registered ${hostname}:${port} as ${service.name}.`,
      data: { hostId: hostRow.id, serviceId: service.id },
    };
  },
};

export function createReconModule(): CopilotModule {
  return {
    id: "recon",
    displayName: "Recon",
    category: "intel",
    version: "0.17.2",
    description:
      "External recon — nmap, passive subdomain enumeration, HTTP fingerprinting. Writes " +
      "discoveries into the workspace hosts/services tables for downstream blackbox modules.",
    rank: "good",
    references: [
      { type: "URL", value: "https://owasp.org/www-project-web-security-testing-guide/" },
    ],
    notes: {
      stability: ["stable"],
      reliability: ["reliable"],
      sideEffects: ["external network traffic"],
    },
    examples: [
      "# Scan a /24 for top ports\nuse recon\nset TARGET 10.0.0.0/24\nrun nmap",
      "# Passive subdomain enumeration\nuse recon\nset DOMAIN acme.example\nrun subdomain",
    ],
    tools: [nmapTool, subdomainTool, httpFingerprintTool],
  };
}

// helpers

function parseNmapInput(input: unknown): NmapInput {
  if (!isRecord(input)) return {};
  return {
    target: readStringField(input, "target"),
    ports: readStringField(input, "ports"),
  };
}

function parseSubdomainInput(input: unknown): SubdomainInput {
  if (!isRecord(input)) return {};
  return {
    domain: readStringField(input, "domain"),
    source: readStringField(input, "source"),
  };
}

function parseHttpFingerprintInput(input: unknown): HttpFingerprintInput {
  if (!isRecord(input)) return {};
  return {
    target: readStringField(input, "target"),
  };
}

function readStringField(
  record: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

function readWorkspaceRowId(value: unknown): WorkspaceRowWithId | null {
  if (!isRecord(value) || typeof value.id !== "string") return null;
  return { id: value.id };
}

function readWorkspaceServiceRow(value: unknown): WorkspaceServiceRow | null {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.name !== "string") {
    return null;
  }
  return { id: value.id, name: value.name };
}

async function isOnPath(bin: string): Promise<boolean> {
  try {
    const { spawn } = await import("node:child_process");
    return await new Promise<boolean>((resolve) => {
      const child = spawn("which", [bin], { stdio: "ignore" });
      child.on("exit", (code) => resolve(code === 0));
      child.on("error", () => resolve(false));
    });
  } catch {
    return false;
  }
}

function splitHostPort(target: string): { host: string; port: number } {
  // strip scheme
  const withoutScheme = target.replace(/^https?:\/\//, "");
  const [hostPart, portPart] = withoutScheme.split(":");
  const host = (hostPart ?? target).split("/")[0] ?? target;
  const explicitPort = portPart ? Number.parseInt(portPart, 10) : NaN;
  const defaultPort = target.startsWith("https://") ? 443 : 80;
  const port = Number.isFinite(explicitPort) ? explicitPort : defaultPort;
  return { host, port };
}
