/**
 * Workspace-entity dispatcher — exposes `hosts`, `services`, `vulns`, `loot`,
 * `notes`, `creds`, `sessions` as read-mostly shell commands.
 *
 * Write paths are deliberately minimal in the shell — operator-facing muations
 * happen through tools/modules. This dispatcher focuses on discoverability:
 * "what do we have in this engagement so far?"
 */

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { SessionManager } from "../../sessions/manager.js";
import { type CredsExportFormat, exportCreds } from "../../workspace/creds-export.js";
import type { PrivateType } from "../../workspace/entities.js";
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
  hosts: "List hosts (`-d <addr>` deletes)",
  services: "List services in the active workspace",
  vulns: "List vulns (`-d <id|name>` deletes)",
  loot: "List / add / save / delete loot (`loot add|save <id> <file>|delete`)",
  notes: "List / add / delete notes (`notes add --type t --data '...'`)",
  creds: "List / add / delete / export creds (`creds -o csv|jtr|hcat`)",
  sessions: "List sessions in the active workspace",
  "workspace:import": "Import a file into the active workspace (sarif | nmap-xml | kz-bundle)",
  "workspace:export": "Export the active workspace to a file (sarif | kz-bundle | markdown)",
  "workspace:github":
    "Post a vulns-summary comment to a PR: `workspace:github <owner>/<repo>#<num> [--dry]`",
};

const IMPORT_FORMATS: ImportFormat[] = ["sarif", "nmap-xml", "kz-bundle"];
const EXPORT_FORMATS: ExportFormat[] = ["sarif", "kz-bundle", "markdown"];

export class WorkspaceDispatcher implements CommandDispatcher {
  readonly name = "workspace";
  readonly commands = COMMANDS;

  constructor(private readonly opts: WorkspaceDispatcherOptions) {}

  async execute(
    cmd: string,
    args: string[],
    ctx: CommandContext,
  ): Promise<CommandResult | undefined> {
    const wid = this.opts.activeWorkspaceId();
    if (!wid) {
      return { output: "[-] No active workspace. Use `workspace use <name>` first." };
    }
    switch (cmd) {
      case "hosts":
        return this.cmd_hosts(args, wid);
      case "services":
        return { output: renderServices(this.listAllServices(wid)) };
      case "vulns":
        return this.cmd_vulns(args, wid);
      case "loot":
        return this.cmd_loot(args, wid, ctx);
      case "notes":
        return this.cmd_notes(args, wid);
      case "creds":
        return this.cmd_creds(args, wid, ctx);
      case "sessions":
        return this.cmd_sessions(args, ctx);
      case "workspace:import":
        return this.cmd_import(args, ctx);
      case "workspace:export":
        return this.cmd_export(args, ctx);
      case "workspace:github":
        return this.cmd_github(args, wid);
      default:
        return undefined;
    }
  }

  // -------------------------------------------------------------------------
  // Entity CRUD
  // -------------------------------------------------------------------------

  private cmd_hosts(args: string[], wid: string): CommandResult {
    if (args[0] === "-d" && args[1]) {
      const hit = this.opts.workspaces.hosts.findByAddress(wid, args[1] as string);
      if (!hit) return { output: `[-] No host at '${args[1]}'.` };
      this.opts.workspaces.hosts.delete(hit.id);
      return { output: `[+] Deleted host ${args[1]}` };
    }
    return { output: renderHosts(this.opts.workspaces.hosts.list(wid)) };
  }

  private cmd_vulns(args: string[], wid: string): CommandResult {
    if (args[0] === "-d" && args[1]) {
      const all = this.opts.workspaces.vulns.listForWorkspace(wid);
      const match = all.find((v) => v.id.startsWith(args[1] as string) || v.name === args[1]);
      if (!match) return { output: `[-] No vuln matches '${args[1]}'.` };
      this.opts.workspaces.vulns.delete(match.id);
      return { output: `[+] Deleted vuln ${match.id.slice(0, 8)} (${match.name})` };
    }
    return { output: renderVulns(this.opts.workspaces.vulns.listForWorkspace(wid)) };
  }

  private cmd_loot(args: string[], wid: string, ctx: CommandContext): CommandResult {
    const sub = args[0];
    if (sub === "add") {
      const flags = parseFlags(args.slice(1));
      if (!flags.name || (!flags.file && !flags.data)) {
        return {
          output:
            "Usage: loot add --type <t> --name <n> [--file <path> | --data '...'] [--host <addr>]",
        };
      }
      let data: Buffer | null = null;
      let contentType: string | null = null;
      if (flags.file) {
        const abs = path.isAbsolute(flags.file) ? flags.file : path.resolve(ctx.cwd, flags.file);
        try {
          data = readFileSync(abs);
          contentType = flags.type ?? null;
        } catch (err) {
          return { output: `[-] loot add: ${err instanceof Error ? err.message : err}` };
        }
      } else if (flags.data) {
        data = Buffer.from(flags.data, "utf8");
        contentType = "text/plain";
      }
      let hostId: string | null = null;
      if (flags.host) {
        const h = this.opts.workspaces.hosts.findByAddress(wid, flags.host);
        if (!h) return { output: `[-] Unknown host '${flags.host}'.` };
        hostId = h.id;
      }
      const insert: Parameters<WorkspaceManager["loot"]["create"]>[0] = {
        workspaceId: wid,
        ltype: flags.type ?? "file",
        name: flags.name,
      };
      if (data) insert.data = data;
      if (contentType) insert.contentType = contentType;
      if (hostId) insert.hostId = hostId;
      if (flags.info) insert.info = flags.info;
      const row = this.opts.workspaces.loot.create(insert);
      return { output: `[+] Loot added: ${row.id.slice(0, 8)} (${row.name})` };
    }
    if (sub === "save" && args[1] && args[2]) {
      const all = this.opts.workspaces.loot.listForWorkspace(wid);
      const match = all.find((l) => l.id.startsWith(args[1] as string));
      if (!match) return { output: `[-] No loot matches '${args[1]}'.` };
      if (!match.data) return { output: "[-] Loot has no data to save." };
      const outPath = path.isAbsolute(args[2] as string)
        ? (args[2] as string)
        : path.resolve(ctx.cwd, args[2] as string);
      writeFileSync(outPath, match.data);
      return { output: `[+] Wrote ${match.data.length} bytes to ${outPath}` };
    }
    if (sub === "delete" && args[1]) {
      const all = this.opts.workspaces.loot.listForWorkspace(wid);
      const match = all.find((l) => l.id.startsWith(args[1] as string));
      if (!match) return { output: `[-] No loot matches '${args[1]}'.` };
      this.opts.workspaces.loot.delete(match.id);
      return { output: `[+] Deleted loot ${match.id.slice(0, 8)}` };
    }
    return { output: renderLoot(this.opts.workspaces.loot.listForWorkspace(wid, args[0])) };
  }

  private cmd_notes(args: string[], wid: string): CommandResult {
    const sub = args[0];
    if (sub === "add") {
      const flags = parseFlags(args.slice(1));
      if (!flags.type || !flags.data) {
        return { output: "Usage: notes add --type <t> --data '...' [--host <addr>]" };
      }
      let hostId: string | null = null;
      if (flags.host) {
        const h = this.opts.workspaces.hosts.findByAddress(wid, flags.host);
        if (!h) return { output: `[-] Unknown host '${flags.host}'.` };
        hostId = h.id;
      }
      const insert: Parameters<WorkspaceManager["notes"]["create"]>[0] = {
        workspaceId: wid,
        ntype: flags.type,
        data: { note: flags.data },
      };
      if (hostId) insert.hostId = hostId;
      const row = this.opts.workspaces.notes.create(insert);
      return { output: `[+] Note added: ${row.id.slice(0, 8)}` };
    }
    if (sub === "delete" && args[1]) {
      const all = this.opts.workspaces.notes.listForWorkspace(wid);
      const match = all.find((n) => n.id.startsWith(args[1] as string));
      if (!match) return { output: `[-] No note matches '${args[1]}'.` };
      this.opts.workspaces.notes.delete(match.id);
      return { output: `[+] Deleted note ${match.id.slice(0, 8)}` };
    }
    return { output: renderNotes(this.opts.workspaces.notes.listForWorkspace(wid, args[0])) };
  }

  private cmd_creds(args: string[], wid: string, ctx: CommandContext): CommandResult {
    const sub = args[0];
    if (sub === "add") {
      const flags = parseFlags(args.slice(1));
      if (!flags.user && !flags.private) {
        return {
          output:
            "Usage: creds add --user <u> --private <p> [--private-type password|ssh_key|token|hash|api_key|cookie|other] [--realm <r>]",
        };
      }
      const insert: Parameters<WorkspaceManager["creds"]["upsert"]>[0] = {
        workspaceId: wid,
      };
      if (flags.user) insert.publicUsername = flags.user;
      if (flags.private) insert.privateData = flags.private;
      const pt = (flags["private-type"] ?? "password") as PrivateType;
      insert.privateType = pt;
      if (flags.realm) insert.realmValue = flags.realm;
      const row = this.opts.workspaces.creds.upsert(insert);
      return {
        output: `[+] Cred added: ${row.id.slice(0, 8)} (${row.publicUsername ?? "<no user>"})`,
      };
    }
    if (sub === "delete" && args[1]) {
      const all = this.opts.workspaces.creds.listForWorkspace(wid);
      const match = all.find((c) => c.id.startsWith(args[1] as string));
      if (!match) return { output: `[-] No cred matches '${args[1]}'.` };
      this.opts.workspaces.creds.delete(match.id);
      return { output: `[+] Deleted cred ${match.id.slice(0, 8)}` };
    }
    if (sub === "-o" && args[1]) {
      const fmt = args[1] as string;
      if (fmt !== "csv" && fmt !== "jtr" && fmt !== "hcat") {
        return { output: "[-] creds -o <csv|jtr|hcat> [file]" };
      }
      const rows = this.opts.workspaces.creds.listForWorkspace(wid);
      const body = exportCreds(rows, fmt as CredsExportFormat);
      const file = args[2];
      if (!file) return { output: body };
      const outPath = path.isAbsolute(file) ? file : path.resolve(ctx.cwd, file);
      writeFileSync(outPath, body, "utf8");
      return { output: `[+] Wrote ${rows.length} creds → ${outPath} (${fmt})` };
    }
    return { output: renderCreds(this.opts.workspaces.creds.listForWorkspace(wid)) };
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

  private async cmd_github(args: string[], wid: string): Promise<CommandResult> {
    const ref = args[0];
    if (!ref) {
      return { output: "Usage: workspace:github <owner>/<repo>#<num> [--dry]" };
    }
    const { parsePrRef, renderGitHubComment, postPrComment } = await import(
      "../../workspace/io/github.js"
    );
    const prRef = parsePrRef(ref);
    if (!prRef) return { output: `[-] Invalid PR ref: ${ref} (expected owner/repo#123)` };
    const dryRun = args.includes("--dry");
    const body = renderGitHubComment(this.opts.workspaces, wid);
    const result = await postPrComment(prRef, body, { dryRun });
    if (dryRun) {
      return {
        output: [
          `[*] DRY RUN — would post to ${prRef.owner}/${prRef.repo}#${prRef.number}`,
          "--- body ---",
          body,
        ].join("\n"),
      };
    }
    if (result.posted) {
      return {
        output: `[+] Posted to ${prRef.owner}/${prRef.repo}#${prRef.number}${
          result.url ? ` → ${result.url}` : ""
        }`,
      };
    }
    return {
      output: `[-] ${result.warning ?? "Unknown error posting comment"}`,
    };
  }

  private async cmd_sessions(args: string[], ctx: CommandContext): Promise<CommandResult> {
    const wid = this.opts.activeWorkspaceId() as string;
    const ws = this.opts.workspaces;
    const sub = args[0];
    if (sub === "-k" && args[1]) {
      const resolved = resolveSessionRef(ws, wid, args[1] as string);
      if (typeof resolved !== "string") return { output: resolved.output };
      if (!this.opts.sessions) return { output: "[-] Session manager not available." };
      await this.opts.sessions.close(resolved, "closed");
      return {};
    }
    if (sub === "-n" && args[1]) {
      // `sessions -n <ref> <alias>` — assign an alias. Empty alias clears it.
      const ref = args[1] as string;
      const alias = args.slice(2).join(" ").trim();
      const resolved = resolveSessionRef(ws, wid, ref);
      if (typeof resolved !== "string") return { output: resolved.output };
      ws.sessions.setAlias(resolved, alias.length > 0 ? alias : null);
      return {
        output:
          alias.length > 0
            ? `[+] Session ${resolved.slice(0, 8)} → ${alias}`
            : `[+] Cleared alias on session ${resolved.slice(0, 8)}`,
      };
    }
    if (sub === "-i" && args[1]) {
      const resolved = resolveSessionRef(ws, wid, args[1] as string);
      if (typeof resolved !== "string") return { output: resolved.output };
      const handle = this.opts.sessions?.getLive(resolved);
      if (!handle?.interact) return { output: "[-] Session not interactive." };
      const input = args.slice(2).join(" ");
      const out = await handle.interact(input, ctx.signal);
      return { output: out };
    }
    // `-I <ref>` (capital): push the interactive REPL dispatcher onto the
    // stack. Operator gets a session-scoped prompt; `back` / `exit` pops.
    if (args[0] === "-I" && args[1]) {
      const resolved = resolveSessionRef(ws, wid, args[1] as string);
      if (typeof resolved !== "string") return { output: resolved.output };
      const handle = this.opts.sessions?.getLive(resolved);
      if (!handle?.interact) return { output: "[-] Session not interactive." };
      const { InteractiveSessionDispatcher } = await import("./session-repl.js");
      const repl = new InteractiveSessionDispatcher(handle, resolved);
      return {
        push: repl,
        output: `[+] Entering session ${resolved.slice(0, 8)} — type 'back' to return.`,
      };
    }
    const openOnly = args.includes("--open");
    const rows = ws.sessions.listForWorkspace(wid, { openOnly });
    return { output: renderSessions(rows) };
  }
}

function resolveSessionRef(
  ws: WorkspaceManager,
  workspaceId: string,
  ref: string,
): string | { output: string } {
  const result = ws.sessions.resolveRef(workspaceId, ref);
  if (!result) return { output: `[-] No session matches '${ref}'.` };
  if ("ambiguous" in result) {
    const pretty = result.ambiguous.map((id) => id.slice(0, 8)).join(", ");
    return { output: `[-] Ambiguous session ref '${ref}' matches: ${pretty}` };
  }
  return result.id;
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
    ["Id", "Alias", "Kind", "State", "Peer", "Via"],
    rows.map((s) => [
      s.id.slice(0, 8),
      s.alias ?? "",
      s.kind,
      s.state,
      s.tunnelPeer ?? "",
      [s.viaModule, s.viaTool].filter(Boolean).join(":"),
    ]),
  );
}

/**
 * Parse `--flag value` argv into a flat record. Supports `--flag=value`,
 * `--flag value`, and bare `--flag` (sets to "true"). Unknown positional
 * tokens are collected under the underscore key.
 */
function parseFlags(args: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  let i = 0;
  while (i < args.length) {
    const tok = args[i] ?? "";
    if (tok.startsWith("--")) {
      const eq = tok.indexOf("=");
      if (eq > 0) {
        out[tok.slice(2, eq)] = tok.slice(eq + 1);
        i++;
      } else {
        const key = tok.slice(2);
        const next = args[i + 1];
        if (next !== undefined && !next.startsWith("--")) {
          out[key] = next;
          i += 2;
        } else {
          out[key] = "true";
          i++;
        }
      }
    } else {
      out._ = `${out._ ?? ""} ${tok}`.trim();
      i++;
    }
  }
  return out;
}
