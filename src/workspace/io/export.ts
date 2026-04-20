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

export type ExportFormat = "sarif" | "kz-bundle";

export function exportToFile(
  ws: WorkspaceManager,
  workspaceId: string,
  format: ExportFormat,
  filePath: string,
): { format: ExportFormat; bytes: number } {
  const content =
    format === "sarif" ? exportSarif(ws, workspaceId) : exportKzBundle(ws, workspaceId);
  writeFileSync(filePath, content, "utf8");
  return { format, bytes: content.length };
}

// ---------------------------------------------------------------------------
// SARIF — minimal schema compatible with what import.ts expects
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// kz-bundle — structural snapshot; re-importable via importKzBundle
// ---------------------------------------------------------------------------

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
