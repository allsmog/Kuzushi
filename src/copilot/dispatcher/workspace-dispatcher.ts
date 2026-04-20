/**
 * Workspace-entity dispatcher — exposes `hosts`, `services`, `vulns`, `loot`,
 * `notes`, `creds`, `sessions` as read-mostly shell commands.
 *
 * Write paths are deliberately minimal in the shell — operator-facing muations
 * happen through tools/modules. This dispatcher focuses on discoverability:
 * "what do we have in this engagement so far?"
 */

import path from "node:path";
import type { SessionManager } from "../../sessions/manager.js";
import { type ExportFormat, exportToFile } from "../../workspace/io/export.js";
import { type ImportFormat, importFile } from "../../workspace/io/import.js";
import type { WorkspaceManager } from "../../workspace/manager.js";
import type { CommandContext, CommandDispatcher, CommandResult } from "./types.js";

export interface WorkspaceDispatcherOptions {
  workspaces: WorkspaceManager;
  /** Resolver for the currently-active workspace ID (if any). */
  activeWorkspaceId: () => string | undefined;
  /** Optional session manager (for `sessions` interact/kill). */
  sessions?: SessionManager;
}

const COMMANDS: Record<string, string> = {
  hosts: "List hosts in the active workspace",
  services: "List services in the active workspace",
  vulns: "List vulnerabilities in the active workspace",
  loot: "List loot captured in the active workspace",
  notes: "List notes in the active workspace",
  creds: "List credentials in the active workspace",
  sessions: "List sessions in the active workspace",
  "workspace:import": "Import a file into the active workspace (sarif | nmap-xml | kz-bundle)",
  "workspace:export": "Export the active workspace to a file (sarif | kz-bundle)",
};

const IMPORT_FORMATS: ImportFormat[] = ["sarif", "nmap-xml", "kz-bundle"];
const EXPORT_FORMATS: ExportFormat[] = ["sarif", "kz-bundle"];

export class WorkspaceDispatcher implements CommandDispatcher {
  readonly name = "workspace";
  readonly commands = COMMANDS;

  constructor(private readonly opts: WorkspaceDispatcherOptions) {}

  async execute(cmd: string, args: string[], ctx: CommandContext): Promise<CommandResult | void> {
    const wid = this.opts.activeWorkspaceId();
    if (!wid) {
      return { output: "[-] No active workspace. Use `workspace use <name>` first." };
    }
    const ws = this.opts.workspaces;
    switch (cmd) {
      case "hosts":
        return { output: renderHosts(ws.hosts.list(wid)) };
      case "services":
        return { output: renderServices(this.listAllServices(wid)) };
      case "vulns":
        return { output: renderVulns(ws.vulns.listForWorkspace(wid)) };
      case "loot":
        return { output: renderLoot(ws.loot.listForWorkspace(wid, args[0])) };
      case "notes":
        return { output: renderNotes(ws.notes.listForWorkspace(wid, args[0])) };
      case "creds":
        return { output: renderCreds(ws.creds.listForWorkspace(wid)) };
      case "sessions":
        return this.cmd_sessions(args, ctx);
      case "workspace:import":
        return this.cmd_import(args, ctx);
      case "workspace:export":
        return this.cmd_export(args, ctx);
      default:
        return undefined;
    }
  }

  complete(cmd: string, partial: string, words: string[]): string[] {
    if (cmd === "workspace:import" && words.length <= 1) {
      return IMPORT_FORMATS.filter((f) => f.startsWith(partial));
    }
    if (cmd === "workspace:export" && words.length <= 1) {
      return EXPORT_FORMATS.filter((f) => f.startsWith(partial));
    }
    return [];
  }

  private cmd_import(args: string[], ctx: CommandContext): CommandResult {
    const wid = this.opts.activeWorkspaceId();
    if (!wid) return { output: "[-] No active workspace." };
    const fmt = args[0];
    const file = args[1];
    if (!fmt || !file) {
      return {
        output: `Usage: workspace:import <${IMPORT_FORMATS.join("|")}> <file>`,
      };
    }
    if (!IMPORT_FORMATS.includes(fmt as ImportFormat)) {
      return { output: `[-] Unknown format: ${fmt}. Use one of: ${IMPORT_FORMATS.join(", ")}` };
    }
    const resolved = path.isAbsolute(file) ? file : path.resolve(ctx.cwd, file);
    try {
      const summary = importFile(this.opts.workspaces, wid, fmt as ImportFormat, resolved);
      const counts = [
        `hosts=${summary.hosts}`,
        `services=${summary.services}`,
        `vulns=${summary.vulns}`,
        `loot=${summary.loot}`,
        `notes=${summary.notes}`,
        `creds=${summary.creds}`,
        `sessions=${summary.sessions}`,
      ].join(" ");
      const lines = [`[+] Imported ${summary.format}: ${counts}`];
      for (const w of summary.warnings) lines.push(`      ! ${w}`);
      return { output: lines.join("\n") };
    } catch (err) {
      return { output: `[-] Import failed: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  private cmd_export(args: string[], ctx: CommandContext): CommandResult {
    const wid = this.opts.activeWorkspaceId();
    if (!wid) return { output: "[-] No active workspace." };
    const fmt = args[0];
    const fileArg = args[1];
    if (!fmt) {
      return { output: `Usage: workspace:export <${EXPORT_FORMATS.join("|")}> [file]` };
    }
    if (!EXPORT_FORMATS.includes(fmt as ExportFormat)) {
      return { output: `[-] Unknown format: ${fmt}. Use one of: ${EXPORT_FORMATS.join(", ")}` };
    }
    const ws = this.opts.workspaces.get(wid);
    const wsName = ws?.name ?? "workspace";
    const defaultFile = fmt === "sarif" ? `${wsName}.sarif` : `${wsName}.kz.json`;
    const file = fileArg ?? defaultFile;
    const resolved = path.isAbsolute(file) ? file : path.resolve(ctx.cwd, file);
    try {
      const { bytes } = exportToFile(this.opts.workspaces, wid, fmt as ExportFormat, resolved);
      return { output: `[+] Exported ${fmt} → ${resolved} (${bytes} bytes)` };
    } catch (err) {
      return { output: `[-] Export failed: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  private listAllServices(workspaceId: string) {
    const hosts = this.opts.workspaces.hosts.list(workspaceId);
    const out: Array<{
      host: string;
      port: number;
      proto: string;
      name: string | null;
      state: string;
    }> = [];
    for (const h of hosts) {
      for (const s of this.opts.workspaces.services.listForHost(h.id)) {
        out.push({
          host: h.hostname ?? h.address,
          port: s.port,
          proto: s.proto,
          name: s.name,
          state: s.state,
        });
      }
    }
    return out;
  }

  private async cmd_sessions(args: string[], ctx: CommandContext): Promise<CommandResult> {
    const wid = this.opts.activeWorkspaceId() as string;
    const ws = this.opts.workspaces;
    const sub = args[0];
    if (sub === "-k" && args[1]) {
      if (!this.opts.sessions) return { output: "[-] Session manager not available." };
      await this.opts.sessions.close(args[1] as string, "closed");
      return {};
    }
    if (sub === "-i" && args[1]) {
      const handle = this.opts.sessions?.getLive(args[1] as string);
      if (!handle?.interact) return { output: "[-] Session not interactive." };
      const input = args.slice(2).join(" ");
      const out = await handle.interact(input, ctx.signal);
      return { output: out };
    }
    const openOnly = args.includes("--open");
    const rows = ws.sessions.listForWorkspace(wid, { openOnly });
    return { output: renderSessions(rows) };
  }
}

// ---------------------------------------------------------------------------
// renderers
// ---------------------------------------------------------------------------

function pad(s: string, w: number): string {
  return s + " ".repeat(Math.max(0, w - s.length));
}

function makeTable(headers: string[], rows: string[][]): string {
  if (rows.length === 0) return "  (none)";
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)));
  const head = headers.map((h, i) => pad(h, widths[i] ?? 0)).join("  ");
  const sep = widths.map((w) => "-".repeat(w)).join("  ");
  const body = rows.map((r) => r.map((c, i) => pad(c ?? "", widths[i] ?? 0)).join("  ")).join("\n");
  return `  ${head}\n  ${sep}\n${body
    .split("\n")
    .map((l) => `  ${l}`)
    .join("\n")}`;
}

function renderHosts(hosts: ReturnType<WorkspaceManager["hosts"]["list"]>): string {
  return makeTable(
    ["Address", "Hostname", "OS", "State"],
    hosts.map((h) => [
      h.address,
      h.hostname ?? "",
      [h.osName, h.osVersion].filter(Boolean).join(" "),
      h.state,
    ]),
  );
}

function renderServices(
  rows: Array<{ host: string; port: number; proto: string; name: string | null; state: string }>,
): string {
  return makeTable(
    ["Host", "Port", "Proto", "Name", "State"],
    rows.map((r) => [r.host, String(r.port), r.proto, r.name ?? "", r.state]),
  );
}

function renderVulns(rows: ReturnType<WorkspaceManager["vulns"]["listForWorkspace"]>): string {
  return makeTable(
    ["Name", "Severity", "Check", "CVEs", "Reason"],
    rows.map((v) => [
      v.name,
      v.severity ?? "",
      v.checkCode ?? "",
      v.references
        .filter((r) => r.type === "CVE")
        .map((r) => r.value)
        .join(",") || "",
      v.checkReason ?? "",
    ]),
  );
}

function renderLoot(rows: ReturnType<WorkspaceManager["loot"]["listForWorkspace"]>): string {
  return makeTable(
    ["Type", "Name", "Size", "Info"],
    rows.map((l) => [
      l.ltype,
      l.name,
      l.data ? `${l.data.length}B` : l.path ? "file" : "",
      l.info ?? "",
    ]),
  );
}

function renderNotes(rows: ReturnType<WorkspaceManager["notes"]["listForWorkspace"]>): string {
  return makeTable(
    ["Type", "Data"],
    rows.map((n) => [n.ntype, JSON.stringify(n.data).slice(0, 60)]),
  );
}

function renderCreds(rows: ReturnType<WorkspaceManager["creds"]["listForWorkspace"]>): string {
  return makeTable(
    ["User", "Private", "Realm", "Origin"],
    rows.map((c) => [
      c.publicUsername ?? "",
      c.privateType ? `${c.privateType}:${(c.privateData ?? "").slice(0, 12)}…` : "",
      c.realmKind ? `${c.realmKind}:${c.realmValue ?? ""}` : "",
      c.originType ?? "",
    ]),
  );
}

function renderSessions(
  rows: ReturnType<WorkspaceManager["sessions"]["listForWorkspace"]>,
): string {
  return makeTable(
    ["Id", "Kind", "State", "Peer", "Via"],
    rows.map((s) => [
      s.id.slice(0, 8),
      s.kind,
      s.state,
      s.tunnelPeer ?? "",
      [s.viaModule, s.viaTool].filter(Boolean).join(":"),
    ]),
  );
}
