/**
 * Workspace importers — `db_import` parity for Kuzushi.
 *
 * Supported formats:
 *   - sarif      : SARIF 2.1.0 results → workspace Vulns. Each result produces one
 *                  vuln keyed by (ruleId + artifact location).
 *   - nmap-xml   : nmap XML → Hosts + Services. Hostnames, OS hints, and open
 *                  services are populated; closed/filtered ports are skipped.
 *   - kz-bundle  : native JSON bundle produced by `workspace:export kz-bundle`.
 *                  Restores the entire entity graph into the target workspace.
 *
 * Format detection is caller-driven (explicit `format` arg) — we don't sniff
 * by extension, because operators invariably hand us mis-named files.
 */

import { readFileSync } from "node:fs";
import type {
  Cred,
  Host,
  Loot,
  Note,
  Service,
  SessionRecord,
  Vuln,
  VulnSeverity,
} from "../entities.js";
import type { WorkspaceManager } from "../manager.js";

export type ImportFormat = "sarif" | "nmap-xml" | "kz-bundle";

export interface ImportSummary {
  format: ImportFormat;
  hosts: number;
  services: number;
  vulns: number;
  loot: number;
  notes: number;
  creds: number;
  sessions: number;
  /** Warnings emitted during parse (malformed rows we skipped). */
  warnings: string[];
}

export function emptySummary(format: ImportFormat): ImportSummary {
  return {
    format,
    hosts: 0,
    services: 0,
    vulns: 0,
    loot: 0,
    notes: 0,
    creds: 0,
    sessions: 0,
    warnings: [],
  };
}

/**
 * Dispatch entry — reads the file and routes to the right adapter.
 */
export function importFile(
  ws: WorkspaceManager,
  workspaceId: string,
  format: ImportFormat,
  filePath: string,
): ImportSummary {
  const raw = readFileSync(filePath, "utf8");
  switch (format) {
    case "sarif":
      return importSarif(ws, workspaceId, raw);
    case "nmap-xml":
      return importNmapXml(ws, workspaceId, raw);
    case "kz-bundle":
      return importKzBundle(ws, workspaceId, raw);
  }
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0
// ---------------------------------------------------------------------------

interface SarifLog {
  runs?: Array<{
    tool?: { driver?: { name?: string; rules?: Array<{ id?: string; name?: string }> } };
    results?: Array<SarifResult>;
  }>;
}

interface SarifResult {
  ruleId?: string;
  level?: "error" | "warning" | "note";
  message?: { text?: string };
  locations?: Array<{ physicalLocation?: { artifactLocation?: { uri?: string } } }>;
  properties?: { severity?: string; cwe?: string[]; cve?: string[] };
}

function sarifLevelToSeverity(level?: string, explicit?: string): VulnSeverity | null {
  const explicitLc = explicit?.toLowerCase();
  if (
    explicitLc === "info" ||
    explicitLc === "low" ||
    explicitLc === "medium" ||
    explicitLc === "high" ||
    explicitLc === "critical"
  ) {
    return explicitLc;
  }
  if (level === "error") return "high";
  if (level === "warning") return "medium";
  if (level === "note") return "low";
  return null;
}

export function importSarif(ws: WorkspaceManager, workspaceId: string, raw: string): ImportSummary {
  const summary = emptySummary("sarif");
  let parsed: SarifLog;
  try {
    parsed = JSON.parse(raw) as SarifLog;
  } catch (err) {
    summary.warnings.push(`SARIF parse failed: ${err instanceof Error ? err.message : err}`);
    return summary;
  }
  for (const run of parsed.runs ?? []) {
    const toolName = run.tool?.driver?.name ?? "sarif";
    for (const result of run.results ?? []) {
      const ruleId = result.ruleId ?? "unknown-rule";
      const loc =
        result.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? "unknown-location";
      const severity = sarifLevelToSeverity(result.level, result.properties?.severity);
      const references = [
        ...(result.properties?.cve ?? []).map((v) => ({ type: "CVE" as const, value: v })),
        ...(result.properties?.cwe ?? []).map((v) => ({ type: "CWE" as const, value: v })),
      ];
      ws.vulns.create({
        workspaceId,
        name: `${ruleId} @ ${loc}`,
        description: result.message?.text ?? null,
        severity,
        references,
        metadata: { tool: toolName, ruleId, location: loc },
      });
      summary.vulns++;
    }
  }
  return summary;
}

// ---------------------------------------------------------------------------
// nmap XML
// ---------------------------------------------------------------------------

/**
 * Minimal nmap-XML reader — we only care about host + service rows. We parse
 * with a scan over the opening tags rather than pulling in a full XML dep.
 * Operators running unusual nmap variants should complain loudly and we'll
 * swap in `fast-xml-parser`.
 */
export function importNmapXml(
  ws: WorkspaceManager,
  workspaceId: string,
  raw: string,
): ImportSummary {
  const summary = emptySummary("nmap-xml");
  const hostBlocks = raw.match(/<host\b[\s\S]*?<\/host>/g) ?? [];
  for (const block of hostBlocks) {
    const address = /<address\s+addr="([^"]+)"\s+addrtype="ipv4"/i.exec(block)?.[1];
    if (!address) {
      summary.warnings.push("nmap: host missing ipv4 address; skipped");
      continue;
    }
    const hostname = /<hostname\s+name="([^"]+)"/i.exec(block)?.[1] ?? null;
    const osName = /<osmatch\s+name="([^"]+)"/i.exec(block)?.[1] ?? null;
    const stateRaw = /<status\s+state="([^"]+)"/i.exec(block)?.[1] ?? "alive";
    const state: Host["state"] =
      stateRaw === "up" ? "alive" : stateRaw === "down" ? "down" : "unknown";
    const host = ws.hosts.upsert({ workspaceId, address, hostname, osName, state });
    summary.hosts++;

    const portBlocks = block.match(/<port\b[\s\S]*?<\/port>/g) ?? [];
    for (const pb of portBlocks) {
      const header = /<port\s+protocol="([^"]+)"\s+portid="(\d+)"/i.exec(pb);
      if (!header) continue;
      const proto = header[1] as Service["proto"];
      const port = Number.parseInt(header[2] ?? "", 10);
      if (!Number.isFinite(port)) continue;
      const portState = /<state\s+state="([^"]+)"/i.exec(pb)?.[1] ?? "unknown";
      if (portState !== "open") continue; // skip closed/filtered
      const svcMatch = /<service\b([^>]*)\/?>/i.exec(pb);
      const svcAttrs = svcMatch?.[1] ?? "";
      const name = /name="([^"]+)"/.exec(svcAttrs)?.[1] ?? null;
      const banner = /product="([^"]+)"/.exec(svcAttrs)?.[1] ?? null;
      ws.services.upsert({
        hostId: host.id,
        port,
        proto,
        name,
        banner,
        state: "open",
      });
      summary.services++;
    }
  }
  return summary;
}

// ---------------------------------------------------------------------------
// Native kz-bundle
// ---------------------------------------------------------------------------

export interface KzBundle {
  schemaVersion: 1;
  snapshotAt: string;
  workspace: { name: string; targets: string[]; metadata: Record<string, unknown> };
  hosts: Array<Omit<Host, "id" | "workspaceId" | "createdAt" | "updatedAt">>;
  services: Array<
    Omit<Service, "id" | "hostId" | "createdAt" | "updatedAt"> & { hostAddress: string }
  >;
  vulns: Array<
    Omit<Vuln, "id" | "workspaceId" | "hostId" | "serviceId" | "createdAt" | "updatedAt">
  >;
  loot: Array<Omit<Loot, "id" | "workspaceId" | "createdAt">>;
  notes: Array<Omit<Note, "id" | "workspaceId" | "createdAt">>;
  creds: Array<Omit<Cred, "id" | "workspaceId" | "createdAt" | "updatedAt">>;
  sessions: Array<Omit<SessionRecord, "id" | "workspaceId" | "openedAt" | "updatedAt">>;
}

export function importKzBundle(
  ws: WorkspaceManager,
  workspaceId: string,
  raw: string,
): ImportSummary {
  const summary = emptySummary("kz-bundle");
  let bundle: KzBundle;
  try {
    bundle = JSON.parse(raw) as KzBundle;
  } catch (err) {
    summary.warnings.push(`kz-bundle parse failed: ${err instanceof Error ? err.message : err}`);
    return summary;
  }
  if (bundle.schemaVersion !== 1) {
    summary.warnings.push(`kz-bundle schemaVersion ${bundle.schemaVersion} not supported`);
    return summary;
  }

  const addressToHost = new Map<string, string>();
  for (const h of bundle.hosts ?? []) {
    const host = ws.hosts.upsert({
      workspaceId,
      address: h.address,
      hostname: h.hostname,
      osName: h.osName,
      osFlavor: h.osFlavor,
      osVersion: h.osVersion,
      arch: h.arch,
      purpose: h.purpose,
      state: h.state,
      comm: h.comm,
      metadata: h.metadata,
    });
    addressToHost.set(h.address, host.id);
    summary.hosts++;
  }
  for (const s of bundle.services ?? []) {
    const hostId = addressToHost.get(s.hostAddress);
    if (!hostId) {
      summary.warnings.push(`service skipped — no host for address ${s.hostAddress}`);
      continue;
    }
    ws.services.upsert({
      hostId,
      port: s.port,
      proto: s.proto,
      name: s.name,
      banner: s.banner,
      state: s.state,
      info: s.info,
    });
    summary.services++;
  }
  for (const v of bundle.vulns ?? []) {
    ws.vulns.create({
      workspaceId,
      name: v.name,
      description: v.description,
      severity: v.severity,
      references: v.references,
      checkCode: v.checkCode,
      checkReason: v.checkReason,
      findingFp: v.findingFp,
      metadata: v.metadata,
    });
    summary.vulns++;
  }
  for (const l of bundle.loot ?? []) {
    const insert: Parameters<typeof ws.loot.create>[0] = {
      workspaceId,
      ltype: l.ltype,
      name: l.name,
      contentType: l.contentType,
      info: l.info,
      metadata: l.metadata,
    };
    if (l.path) insert.path = l.path;
    if (l.data) insert.data = l.data;
    if (l.hostId) insert.hostId = l.hostId;
    ws.loot.create(insert);
    summary.loot++;
  }
  for (const n of bundle.notes ?? []) {
    ws.notes.create({
      workspaceId,
      ntype: n.ntype,
      data: n.data,
      hostId: n.hostId,
      serviceId: n.serviceId,
    });
    summary.notes++;
  }
  for (const c of bundle.creds ?? []) {
    ws.creds.create({
      workspaceId,
      publicUsername: c.publicUsername,
      privateType: c.privateType,
      privateData: c.privateData,
      realmKind: c.realmKind,
      realmValue: c.realmValue,
      originType: c.originType,
      originDetail: c.originDetail,
      metadata: c.metadata,
    });
    summary.creds++;
  }
  for (const sess of bundle.sessions ?? []) {
    ws.sessions.create({
      workspaceId,
      kind: sess.kind,
      state: sess.state,
      description: sess.description,
      tunnelPeer: sess.tunnelPeer,
      tunnelLocal: sess.tunnelLocal,
      viaModule: sess.viaModule,
      viaTool: sess.viaTool,
      metadata: sess.metadata,
    });
    summary.sessions++;
  }
  return summary;
}
