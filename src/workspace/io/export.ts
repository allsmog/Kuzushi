/**
 * Workspace exporters — `db_export` parity.
 *
 * Supported formats:
 *   - sarif      : Active workspace vulns → SARIF 2.1.0 (round-trip with `import.ts`).
 *                  For the richer pipeline SARIF (with triage + verify fields), use
 *                  `report-sarif.ts#generateSarifReport` instead.
 *   - kz-bundle  : Full entity-graph snapshot. Round-trips through `import.ts`.
 */

import { writeFileSync } from "node:fs";
import type { WorkspaceManager } from "../manager.js";
import type { KzBundle } from "./import.js";

export type ExportFormat = "sarif" | "kz-bundle" | "markdown";

export function exportToFile(
  ws: WorkspaceManager,
  workspaceId: string,
  format: ExportFormat,
  filePath: string,
): { format: ExportFormat; bytes: number } {
  const content =
    format === "sarif"
      ? exportSarif(ws, workspaceId)
      : format === "markdown"
        ? exportMarkdown(ws, workspaceId)
        : exportKzBundle(ws, workspaceId);
  writeFileSync(filePath, content, "utf8");
  return { format, bytes: content.length };
}

// SARIF — minimal schema compatible with what import.ts expects

const SEVERITY_TO_LEVEL: Record<string, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export function exportSarif(ws: WorkspaceManager, workspaceId: string): string {
  const vulns = ws.vulns.listForWorkspace(workspaceId);
  const results = vulns.map((v) => ({
    ruleId: String(
      (v.metadata as { ruleId?: string })?.ruleId ?? v.name.split("@")[0]?.trim() ?? "kuzushi-rule",
    ),
    level: v.severity ? SEVERITY_TO_LEVEL[v.severity] : "note",
    message: { text: v.description ?? v.name },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: String(
              (v.metadata as { location?: string })?.location ??
                v.name.split("@")[1]?.trim() ??
                "unknown",
            ),
          },
        },
      },
    ],
    properties: {
      severity: v.severity ?? "info",
      cve: v.references.filter((r) => r.type === "CVE").map((r) => r.value),
      cwe: v.references.filter((r) => r.type === "CWE").map((r) => r.value),
    },
  }));
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "kuzushi", informationUri: "https://kuzushi.dev" } },
        results,
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

// kz-bundle — structural snapshot; re-importable via importKzBundle

export function exportKzBundle(ws: WorkspaceManager, workspaceId: string): string {
  const workspace = ws.get(workspaceId);
  if (!workspace) throw new Error(`Unknown workspace: ${workspaceId}`);

  const hosts = ws.hosts.list(workspaceId);
  const hostIdToAddress = new Map(hosts.map((h) => [h.id, h.address]));

  const services = hosts.flatMap((h) =>
    ws.services.listForHost(h.id).map((s) => ({
      hostAddress: h.address,
      port: s.port,
      proto: s.proto,
      name: s.name,
      banner: s.banner,
      state: s.state,
      info: s.info,
    })),
  );

  const vulns = ws.vulns.listForWorkspace(workspaceId).map((v) => ({
    name: v.name,
    description: v.description,
    severity: v.severity,
    references: v.references,
    checkCode: v.checkCode,
    checkReason: v.checkReason,
    findingFp: v.findingFp,
    metadata: v.metadata,
  }));

  const loot = ws.loot.listForWorkspace(workspaceId).map((l) => ({
    ltype: l.ltype,
    name: l.name,
    contentType: l.contentType,
    info: l.info,
    path: l.path,
    data: l.data,
    hostId: l.hostId,
    metadata: l.metadata,
  }));

  const notes = ws.notes.listForWorkspace(workspaceId).map((n) => ({
    ntype: n.ntype,
    data: n.data,
    hostId: n.hostId,
    serviceId: n.serviceId,
  }));

  const creds = ws.creds.listForWorkspace(workspaceId).map((c) => ({
    publicUsername: c.publicUsername,
    privateType: c.privateType,
    privateData: c.privateData,
    realmKind: c.realmKind,
    realmValue: c.realmValue,
    originType: c.originType,
    originDetail: c.originDetail,
    metadata: c.metadata,
  }));

  const sessions = ws.sessions.listForWorkspace(workspaceId).map((s) => ({
    kind: s.kind,
    state: s.state,
    alias: s.alias,
    description: s.description,
    tunnelPeer: s.tunnelPeer,
    tunnelLocal: s.tunnelLocal,
    viaModule: s.viaModule,
    viaTool: s.viaTool,
    metadata: s.metadata,
  }));

  const bundle: KzBundle = {
    schemaVersion: 1,
    snapshotAt: new Date().toISOString(),
    workspace: {
      name: workspace.name,
      targets: workspace.targets,
      metadata: workspace.metadata,
    },
    hosts: hosts.map((h) => ({
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
    })),
    services,
    vulns,
    loot,
    notes,
    creds,
    sessions,
  } as KzBundle;

  // hostIdToAddress is used only to aid future denormalization; suppress the
  // unused-variable warning without leaking it into the public surface.
  void hostIdToAddress;

  return `${JSON.stringify(bundle, null, 2)}\n`;
}

// Markdown engagement report — human-readable summary

/**
 * Render a workspace as a markdown engagement report. Distinct from SARIF
 * (which targets CI ingestion) — this one is meant to be pasted into a
 * handoff ticket, shared with a client, or archived as the post-engagement
 * artifact.
 *
 * Layout: workspace header → host/service inventory → vulns grouped by
 * severity with CVE/CWE references → credential summary → loot manifest →
 * session log.
 */
export function exportMarkdown(ws: WorkspaceManager, workspaceId: string): string {
  const workspace = ws.get(workspaceId);
  if (!workspace) throw new Error(`Unknown workspace: ${workspaceId}`);

  const hosts = ws.hosts.list(workspaceId);
  const vulns = ws.vulns.listForWorkspace(workspaceId);
  const loot = ws.loot.listForWorkspace(workspaceId);
  const creds = ws.creds.listForWorkspace(workspaceId);
  const notes = ws.notes.listForWorkspace(workspaceId);
  const sessions = ws.sessions.listForWorkspace(workspaceId);

  const lines: string[] = [];
  lines.push(`# Engagement report — ${workspace.name}`);
  lines.push("");
  lines.push(`_Generated ${new Date().toISOString()}_`);
  if (workspace.targets.length > 0) {
    lines.push("");
    lines.push(`**Targets:** ${workspace.targets.join(", ")}`);
  }
  const cost = workspace.metadata.totalCostUsd;
  if (typeof cost === "number" && cost > 0) {
    lines.push(`**Cost:** $${cost.toFixed(2)}`);
  }

  // ── Summary counts ──
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- **${hosts.length}** host${hosts.length === 1 ? "" : "s"}`);
  lines.push(`- **${vulns.length}** vuln${vulns.length === 1 ? "" : "s"}`);
  lines.push(`- **${creds.length}** credential${creds.length === 1 ? "" : "s"}`);
  lines.push(`- **${loot.length}** loot item${loot.length === 1 ? "" : "s"}`);
  lines.push(`- **${notes.length}** note${notes.length === 1 ? "" : "s"}`);
  lines.push(`- **${sessions.length}** session${sessions.length === 1 ? "" : "s"}`);

  // ── Hosts + services ──
  if (hosts.length > 0) {
    lines.push("");
    lines.push("## Hosts");
    lines.push("");
    for (const h of hosts) {
      const svc = ws.services.listForHost(h.id);
      const svcLine =
        svc.length === 0 ? "" : `  — ${svc.length} open service${svc.length === 1 ? "" : "s"}`;
      lines.push(`### ${h.hostname ?? h.address}${svcLine}`);
      lines.push("");
      if (h.address !== h.hostname) lines.push(`- **Address:** ${h.address}`);
      if (h.osName) lines.push(`- **OS:** ${[h.osName, h.osVersion].filter(Boolean).join(" ")}`);
      if (svc.length > 0) {
        lines.push("");
        lines.push("| Port | Proto | Service | Banner |");
        lines.push("| ---- | ----- | ------- | ------ |");
        for (const s of svc) {
          lines.push(`| ${s.port} | ${s.proto} | ${s.name ?? ""} | ${s.banner ?? ""} |`);
        }
      }
      lines.push("");
    }
  }

  // ── Vulns by severity ──
  if (vulns.length > 0) {
    lines.push("## Vulnerabilities");
    lines.push("");
    const order: Array<"critical" | "high" | "medium" | "low" | "info"> = [
      "critical",
      "high",
      "medium",
      "low",
      "info",
    ];
    for (const sev of order) {
      const bucket = vulns.filter((v) => v.severity === sev);
      if (bucket.length === 0) continue;
      lines.push(`### ${sev.toUpperCase()} (${bucket.length})`);
      lines.push("");
      for (const v of bucket) {
        lines.push(`#### ${v.name}`);
        if (v.description) lines.push("");
        if (v.description) lines.push(v.description);
        const refs = v.references ?? [];
        if (refs.length > 0) {
          lines.push("");
          lines.push(`**References:** ${refs.map((r) => `${r.type}:${r.value}`).join(" · ")}`);
        }
        if (v.checkCode) {
          lines.push(`**CheckCode:** ${v.checkCode}${v.checkReason ? ` — ${v.checkReason}` : ""}`);
        }
        lines.push("");
      }
    }
  }

  // ── Credentials (redacted private data) ──
  if (creds.length > 0) {
    lines.push("## Credentials");
    lines.push("");
    lines.push("| User | Type | Realm | Origin |");
    lines.push("| ---- | ---- | ----- | ------ |");
    for (const c of creds) {
      const priv = c.privateType ? `${c.privateType} (len=${(c.privateData ?? "").length})` : "";
      lines.push(
        `| ${c.publicUsername ?? ""} | ${priv} | ${c.realmKind ? `${c.realmKind}:${c.realmValue ?? ""}` : ""} | ${c.originType ?? ""} |`,
      );
    }
    lines.push("");
  }

  // ── Loot manifest ──
  if (loot.length > 0) {
    lines.push("## Loot");
    lines.push("");
    lines.push("| Id | Type | Name | Size |");
    lines.push("| -- | ---- | ---- | ---- |");
    for (const l of loot) {
      const size = l.data ? `${l.data.length}B` : l.path ? "file" : "";
      lines.push(`| ${l.id.slice(0, 8)} | ${l.ltype} | ${l.name} | ${size} |`);
    }
    lines.push("");
  }

  // ── Sessions ──
  if (sessions.length > 0) {
    lines.push("## Sessions");
    lines.push("");
    lines.push("| Id | Alias | Kind | State | Opened |");
    lines.push("| -- | ----- | ---- | ----- | ------ |");
    for (const s of sessions) {
      lines.push(
        `| ${s.id.slice(0, 8)} | ${s.alias ?? ""} | ${s.kind} | ${s.state} | ${s.openedAt.slice(0, 16)} |`,
      );
    }
    lines.push("");
  }

  return lines.join("\n") + "\n";
}
