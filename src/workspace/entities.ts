/**
 * Workspace entity data layer — host/service/vuln/loot/note/cred/session.
 *
 * All records are workspace-scoped via FKs defined in migration 101.
 * Layout mirrors Metasploit's db_manager modules (lib/msf/core/db_manager/*):
 * Core (credential identity) + optional Logins linking credentials to services.
 *
 * IDs are UUIDs, dates are ISO strings, JSON blobs use safe parse/stringify.
 */

import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import type { ModuleReference } from "../modules/types.js";
import type { CheckCodeKind } from "../triage/checkcode.js";

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

export interface Host {
  id: string;
  workspaceId: string;
  address: string;
  hostname: string | null;
  osName: string | null;
  osFlavor: string | null;
  osVersion: string | null;
  arch: string | null;
  purpose: string | null;
  state: "alive" | "down" | "unknown";
  comm: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export type HostUpsert = Pick<Host, "workspaceId" | "address"> &
  Partial<Omit<Host, "id" | "workspaceId" | "address" | "createdAt" | "updatedAt">>;

export class HostStore {
  constructor(private readonly db: Database.Database) {}

  upsert(input: HostUpsert): Host {
    const existing = this.findByAddress(input.workspaceId, input.address);
    if (existing) {
      this.update(existing.id, input);
      return this.get(existing.id) as Host;
    }
    return this.create(input);
  }

  create(input: HostUpsert): Host {
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO hosts (id, workspace_id, address, hostname, os_name, os_flavor, os_version,
                            arch, purpose, state, comm, metadata_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.workspaceId,
        input.address,
        input.hostname ?? null,
        input.osName ?? null,
        input.osFlavor ?? null,
        input.osVersion ?? null,
        input.arch ?? null,
        input.purpose ?? null,
        input.state ?? "alive",
        input.comm ?? null,
        JSON.stringify(input.metadata ?? {}),
      );
    return this.get(id) as Host;
  }

  update(id: string, patch: Partial<Host>): void {
    const existing = this.get(id);
    if (!existing) return;
    const merged = { ...existing, ...patch };
    this.db
      .prepare(
        `UPDATE hosts SET hostname=?, os_name=?, os_flavor=?, os_version=?, arch=?,
                          purpose=?, state=?, comm=?, metadata_json=?, updated_at=datetime('now')
         WHERE id=?`,
      )
      .run(
        merged.hostname ?? null,
        merged.osName ?? null,
        merged.osFlavor ?? null,
        merged.osVersion ?? null,
        merged.arch ?? null,
        merged.purpose ?? null,
        merged.state,
        merged.comm ?? null,
        JSON.stringify(merged.metadata ?? {}),
        id,
      );
  }

  get(id: string): Host | null {
    const row = this.db.prepare("SELECT * FROM hosts WHERE id = ?").get(id) as HostRow | undefined;
    return row ? rowToHost(row) : null;
  }

  findByAddress(workspaceId: string, address: string): Host | null {
    const row = this.db
      .prepare("SELECT * FROM hosts WHERE workspace_id = ? AND address = ?")
      .get(workspaceId, address) as HostRow | undefined;
    return row ? rowToHost(row) : null;
  }

  list(workspaceId: string): Host[] {
    const rows = this.db
      .prepare("SELECT * FROM hosts WHERE workspace_id = ? ORDER BY address")
      .all(workspaceId) as HostRow[];
    return rows.map(rowToHost);
  }

  delete(id: string): void {
    this.db.prepare("DELETE FROM hosts WHERE id = ?").run(id);
  }
}

interface HostRow {
  id: string;
  workspace_id: string;
  address: string;
  hostname: string | null;
  os_name: string | null;
  os_flavor: string | null;
  os_version: string | null;
  arch: string | null;
  purpose: string | null;
  state: "alive" | "down" | "unknown";
  comm: string | null;
  metadata_json: string;
  created_at: string;
  updated_at: string;
}

function rowToHost(row: HostRow): Host {
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    address: row.address,
    hostname: row.hostname,
    osName: row.os_name,
    osFlavor: row.os_flavor,
    osVersion: row.os_version,
    arch: row.arch,
    purpose: row.purpose,
    state: row.state,
    comm: row.comm,
    metadata: safeJson(row.metadata_json, {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export interface Service {
  id: string;
  hostId: string;
  port: number;
  proto: "tcp" | "udp" | "icmp" | "sctp";
  name: string | null;
  banner: string | null;
  state: "open" | "closed" | "filtered" | "unknown";
  info: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export type ServiceUpsert = Pick<Service, "hostId" | "port"> &
  Partial<Omit<Service, "id" | "hostId" | "port" | "createdAt" | "updatedAt">>;

export class ServiceStore {
  constructor(private readonly db: Database.Database) {}

  upsert(input: ServiceUpsert): Service {
    const proto = input.proto ?? "tcp";
    const existing = this.findByEndpoint(input.hostId, input.port, proto);
    if (existing) {
      this.update(existing.id, input);
      return this.get(existing.id) as Service;
    }
    return this.create({ ...input, proto });
  }

  create(input: ServiceUpsert): Service {
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO services (id, host_id, port, proto, name, banner, state, info_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.hostId,
        input.port,
        input.proto ?? "tcp",
        input.name ?? null,
        input.banner ?? null,
        input.state ?? "open",
        JSON.stringify(input.info ?? {}),
      );
    return this.get(id) as Service;
  }

  update(id: string, patch: Partial<Service>): void {
    const existing = this.get(id);
    if (!existing) return;
    const merged = { ...existing, ...patch };
    this.db
      .prepare(
        `UPDATE services SET name=?, banner=?, state=?, info_json=?, updated_at=datetime('now')
         WHERE id=?`,
      )
      .run(
        merged.name ?? null,
        merged.banner ?? null,
        merged.state,
        JSON.stringify(merged.info ?? {}),
        id,
      );
  }

  get(id: string): Service | null {
    const row = this.db.prepare("SELECT * FROM services WHERE id = ?").get(id) as
      | ServiceRow
      | undefined;
    return row ? rowToService(row) : null;
  }

  findByEndpoint(hostId: string, port: number, proto: Service["proto"]): Service | null {
    const row = this.db
      .prepare("SELECT * FROM services WHERE host_id = ? AND port = ? AND proto = ?")
      .get(hostId, port, proto) as ServiceRow | undefined;
    return row ? rowToService(row) : null;
  }

  listForHost(hostId: string): Service[] {
    const rows = this.db
      .prepare("SELECT * FROM services WHERE host_id = ? ORDER BY port")
      .all(hostId) as ServiceRow[];
    return rows.map(rowToService);
  }

  delete(id: string): void {
    this.db.prepare("DELETE FROM services WHERE id = ?").run(id);
  }
}

interface ServiceRow {
  id: string;
  host_id: string;
  port: number;
  proto: Service["proto"];
  name: string | null;
  banner: string | null;
  state: Service["state"];
  info_json: string;
  created_at: string;
  updated_at: string;
}

function rowToService(row: ServiceRow): Service {
  return {
    id: row.id,
    hostId: row.host_id,
    port: row.port,
    proto: row.proto,
    name: row.name,
    banner: row.banner,
    state: row.state,
    info: safeJson(row.info_json, {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ---------------------------------------------------------------------------
// Vulns
// ---------------------------------------------------------------------------

export type VulnSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface Vuln {
  id: string;
  workspaceId: string;
  hostId: string | null;
  serviceId: string | null;
  findingFp: string | null;
  name: string;
  description: string | null;
  severity: VulnSeverity | null;
  references: ModuleReference[];
  checkCode: CheckCodeKind | null;
  checkReason: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export type VulnInsert = Pick<Vuln, "workspaceId" | "name"> &
  Partial<Omit<Vuln, "id" | "workspaceId" | "name" | "createdAt" | "updatedAt">>;

export class VulnStore {
  constructor(private readonly db: Database.Database) {}

  create(input: VulnInsert): Vuln {
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO vulns (id, workspace_id, host_id, service_id, finding_fp, name, description,
                            severity, references_json, check_code, check_reason, metadata_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.workspaceId,
        input.hostId ?? null,
        input.serviceId ?? null,
        input.findingFp ?? null,
        input.name,
        input.description ?? null,
        input.severity ?? null,
        JSON.stringify(input.references ?? []),
        input.checkCode ?? null,
        input.checkReason ?? null,
        JSON.stringify(input.metadata ?? {}),
      );
    return this.get(id) as Vuln;
  }

  get(id: string): Vuln | null {
    const row = this.db.prepare("SELECT * FROM vulns WHERE id = ?").get(id) as VulnRow | undefined;
    return row ? rowToVuln(row) : null;
  }

  listForWorkspace(workspaceId: string): Vuln[] {
    const rows = this.db
      .prepare("SELECT * FROM vulns WHERE workspace_id = ? ORDER BY created_at DESC")
      .all(workspaceId) as VulnRow[];
    return rows.map(rowToVuln);
  }

  delete(id: string): void {
    this.db.prepare("DELETE FROM vulns WHERE id = ?").run(id);
  }
}

interface VulnRow {
  id: string;
  workspace_id: string;
  host_id: string | null;
  service_id: string | null;
  finding_fp: string | null;
  name: string;
  description: string | null;
  severity: VulnSeverity | null;
  references_json: string;
  check_code: CheckCodeKind | null;
  check_reason: string | null;
  metadata_json: string;
  created_at: string;
  updated_at: string;
}

function rowToVuln(row: VulnRow): Vuln {
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    hostId: row.host_id,
    serviceId: row.service_id,
    findingFp: row.finding_fp,
    name: row.name,
    description: row.description,
    severity: row.severity,
    references: safeJson(row.references_json, [] as ModuleReference[]),
    checkCode: row.check_code,
    checkReason: row.check_reason,
    metadata: safeJson(row.metadata_json, {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ---------------------------------------------------------------------------
// Loot
// ---------------------------------------------------------------------------

export interface Loot {
  id: string;
  workspaceId: string;
  hostId: string | null;
  ltype: string;
  contentType: string | null;
  name: string;
  path: string | null;
  data: Buffer | null;
  info: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export type LootInsert = Pick<Loot, "workspaceId" | "ltype" | "name"> &
  Partial<Omit<Loot, "id" | "createdAt">>;

export class LootStore {
  constructor(private readonly db: Database.Database) {}

  create(input: LootInsert): Loot {
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO loot (id, workspace_id, host_id, ltype, content_type, name, path, data, info, metadata_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.workspaceId,
        input.hostId ?? null,
        input.ltype,
        input.contentType ?? null,
        input.name,
        input.path ?? null,
        input.data ?? null,
        input.info ?? null,
        JSON.stringify(input.metadata ?? {}),
      );
    return this.get(id) as Loot;
  }

  get(id: string): Loot | null {
    const row = this.db.prepare("SELECT * FROM loot WHERE id = ?").get(id) as LootRow | undefined;
    return row ? rowToLoot(row) : null;
  }

  listForWorkspace(workspaceId: string, ltype?: string): Loot[] {
    const rows = ltype
      ? (this.db
          .prepare(
            "SELECT * FROM loot WHERE workspace_id = ? AND ltype = ? ORDER BY created_at DESC",
          )
          .all(workspaceId, ltype) as LootRow[])
      : (this.db
          .prepare("SELECT * FROM loot WHERE workspace_id = ? ORDER BY created_at DESC")
          .all(workspaceId) as LootRow[]);
    return rows.map(rowToLoot);
  }

  delete(id: string): void {
    this.db.prepare("DELETE FROM loot WHERE id = ?").run(id);
  }
}

interface LootRow {
  id: string;
  workspace_id: string;
  host_id: string | null;
  ltype: string;
  content_type: string | null;
  name: string;
  path: string | null;
  data: Buffer | null;
  info: string | null;
  metadata_json: string;
  created_at: string;
}

function rowToLoot(row: LootRow): Loot {
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    hostId: row.host_id,
    ltype: row.ltype,
    contentType: row.content_type,
    name: row.name,
    path: row.path,
    data: row.data,
    info: row.info,
    metadata: safeJson(row.metadata_json, {}),
    createdAt: row.created_at,
  };
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------

export interface Note {
  id: string;
  workspaceId: string;
  hostId: string | null;
  serviceId: string | null;
  ntype: string;
  data: Record<string, unknown>;
  createdAt: string;
}

export type NoteInsert = Pick<Note, "workspaceId" | "ntype"> &
  Partial<Omit<Note, "id" | "createdAt">>;

export class NoteStore {
  constructor(private readonly db: Database.Database) {}

  create(input: NoteInsert): Note {
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO notes (id, workspace_id, host_id, service_id, ntype, data_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.workspaceId,
        input.hostId ?? null,
        input.serviceId ?? null,
        input.ntype,
        JSON.stringify(input.data ?? {}),
      );
    return this.get(id) as Note;
  }

  get(id: string): Note | null {
    const row = this.db.prepare("SELECT * FROM notes WHERE id = ?").get(id) as NoteRow | undefined;
    return row ? rowToNote(row) : null;
  }

  listForWorkspace(workspaceId: string, ntype?: string): Note[] {
    const rows = ntype
      ? (this.db
          .prepare(
            "SELECT * FROM notes WHERE workspace_id = ? AND ntype = ? ORDER BY created_at DESC",
          )
          .all(workspaceId, ntype) as NoteRow[])
      : (this.db
          .prepare("SELECT * FROM notes WHERE workspace_id = ? ORDER BY created_at DESC")
          .all(workspaceId) as NoteRow[]);
    return rows.map(rowToNote);
  }

  delete(id: string): void {
    this.db.prepare("DELETE FROM notes WHERE id = ?").run(id);
  }
}

interface NoteRow {
  id: string;
  workspace_id: string;
  host_id: string | null;
  service_id: string | null;
  ntype: string;
  data_json: string;
  created_at: string;
}

function rowToNote(row: NoteRow): Note {
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    hostId: row.host_id,
    serviceId: row.service_id,
    ntype: row.ntype,
    data: safeJson(row.data_json, {}),
    createdAt: row.created_at,
  };
}

// ---------------------------------------------------------------------------
// Creds (Metasploit: Core + Public + Private + Realm)
// ---------------------------------------------------------------------------

export type PrivateType =
  | "password"
  | "hash"
  | "ssh_key"
  | "token"
  | "api_key"
  | "cookie"
  | "other";

export interface Cred {
  id: string;
  workspaceId: string;
  publicUsername: string | null;
  privateType: PrivateType | null;
  privateData: string | null;
  realmKind: string | null;
  realmValue: string | null;
  originType: string | null;
  originDetail: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export type CredInsert = Pick<Cred, "workspaceId"> &
  Partial<Omit<Cred, "id" | "workspaceId" | "createdAt" | "updatedAt">>;

export interface CredLogin {
  id: string;
  credId: string;
  serviceId: string;
  status: "untried" | "successful" | "failed" | "locked_out" | "disabled";
  accessLevel: string | null;
  lastTriedAt: string | null;
  createdAt: string;
}

export class CredStore {
  constructor(private readonly db: Database.Database) {}

  upsert(input: CredInsert): Cred {
    // Dedupe by (workspace, public, private_type, private_data, realm_kind, realm_value).
    const existing = this.db
      .prepare(
        `SELECT * FROM creds
           WHERE workspace_id = ?
             AND IFNULL(public_username,'') = IFNULL(?, '')
             AND IFNULL(private_type, '')   = IFNULL(?, '')
             AND IFNULL(private_data, '')   = IFNULL(?, '')
             AND IFNULL(realm_kind, '')     = IFNULL(?, '')
             AND IFNULL(realm_value, '')    = IFNULL(?, '')`,
      )
      .get(
        input.workspaceId,
        input.publicUsername ?? null,
        input.privateType ?? null,
        input.privateData ?? null,
        input.realmKind ?? null,
        input.realmValue ?? null,
      ) as CredRow | undefined;
    if (existing) return rowToCred(existing);
    return this.create(input);
  }

  create(input: CredInsert): Cred {
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO creds (id, workspace_id, public_username, private_type, private_data,
                            realm_kind, realm_value, origin_type, origin_detail, metadata_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.workspaceId,
        input.publicUsername ?? null,
        input.privateType ?? null,
        input.privateData ?? null,
        input.realmKind ?? null,
        input.realmValue ?? null,
        input.originType ?? null,
        input.originDetail ?? null,
        JSON.stringify(input.metadata ?? {}),
      );
    return this.get(id) as Cred;
  }

  get(id: string): Cred | null {
    const row = this.db.prepare("SELECT * FROM creds WHERE id = ?").get(id) as CredRow | undefined;
    return row ? rowToCred(row) : null;
  }

  listForWorkspace(workspaceId: string): Cred[] {
    const rows = this.db
      .prepare("SELECT * FROM creds WHERE workspace_id = ? ORDER BY created_at DESC")
      .all(workspaceId) as CredRow[];
    return rows.map(rowToCred);
  }

  delete(id: string): void {
    this.db.prepare("DELETE FROM creds WHERE id = ?").run(id);
  }

  // --- Logins ---

  recordLogin(input: Pick<CredLogin, "credId" | "serviceId"> & Partial<CredLogin>): CredLogin {
    const existing = this.db
      .prepare("SELECT * FROM cred_logins WHERE cred_id = ? AND service_id = ?")
      .get(input.credId, input.serviceId) as CredLoginRow | undefined;
    if (existing) {
      this.db
        .prepare(
          `UPDATE cred_logins SET status=?, access_level=?, last_tried_at=datetime('now')
           WHERE id=?`,
        )
        .run(
          input.status ?? existing.status,
          input.accessLevel ?? existing.access_level,
          existing.id,
        );
      return rowToCredLogin(
        this.db.prepare("SELECT * FROM cred_logins WHERE id=?").get(existing.id) as CredLoginRow,
      );
    }
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO cred_logins (id, cred_id, service_id, status, access_level, last_tried_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))`,
      )
      .run(id, input.credId, input.serviceId, input.status ?? "untried", input.accessLevel ?? null);
    return rowToCredLogin(
      this.db.prepare("SELECT * FROM cred_logins WHERE id=?").get(id) as CredLoginRow,
    );
  }

  loginsFor(credId: string): CredLogin[] {
    const rows = this.db
      .prepare("SELECT * FROM cred_logins WHERE cred_id = ?")
      .all(credId) as CredLoginRow[];
    return rows.map(rowToCredLogin);
  }
}

interface CredRow {
  id: string;
  workspace_id: string;
  public_username: string | null;
  private_type: PrivateType | null;
  private_data: string | null;
  realm_kind: string | null;
  realm_value: string | null;
  origin_type: string | null;
  origin_detail: string | null;
  metadata_json: string;
  created_at: string;
  updated_at: string;
}

function rowToCred(row: CredRow): Cred {
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    publicUsername: row.public_username,
    privateType: row.private_type,
    privateData: row.private_data,
    realmKind: row.realm_kind,
    realmValue: row.realm_value,
    originType: row.origin_type,
    originDetail: row.origin_detail,
    metadata: safeJson(row.metadata_json, {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

interface CredLoginRow {
  id: string;
  cred_id: string;
  service_id: string;
  status: CredLogin["status"];
  access_level: string | null;
  last_tried_at: string | null;
  created_at: string;
}

function rowToCredLogin(row: CredLoginRow): CredLogin {
  return {
    id: row.id,
    credId: row.cred_id,
    serviceId: row.service_id,
    status: row.status,
    accessLevel: row.access_level,
    lastTriedAt: row.last_tried_at,
    createdAt: row.created_at,
  };
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export interface SessionRecord {
  id: string;
  workspaceId: string;
  hostId: string | null;
  serviceId: string | null;
  kind: string;
  state: "open" | "closed" | "error";
  tunnelPeer: string | null;
  tunnelLocal: string | null;
  /** Operator-assigned human-friendly name (msfconsole `sessions -n`). */
  alias: string | null;
  description: string | null;
  viaModule: string | null;
  viaTool: string | null;
  openedAt: string;
  closedAt: string | null;
  metadata: Record<string, unknown>;
}

export type SessionInsert = Pick<SessionRecord, "workspaceId" | "kind"> &
  Partial<Omit<SessionRecord, "id" | "openedAt">>;

export class SessionStore {
  constructor(private readonly db: Database.Database) {}

  create(input: SessionInsert): SessionRecord {
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO sessions (id, workspace_id, host_id, service_id, kind, state,
                               tunnel_peer, tunnel_local, alias, description, via_module, via_tool, metadata_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.workspaceId,
        input.hostId ?? null,
        input.serviceId ?? null,
        input.kind,
        input.state ?? "open",
        input.tunnelPeer ?? null,
        input.tunnelLocal ?? null,
        input.alias ?? null,
        input.description ?? null,
        input.viaModule ?? null,
        input.viaTool ?? null,
        JSON.stringify(input.metadata ?? {}),
      );
    return this.get(id) as SessionRecord;
  }

  /**
   * Resolve a short prefix, full id, or alias to a session id. Returns
   * the id on unique match, null if no match, or an array on ambiguity
   * (caller decides how to render).
   */
  resolveRef(workspaceId: string, ref: string): { id: string } | { ambiguous: string[] } | null {
    if (!ref) return null;
    const aliased = this.db
      .prepare("SELECT id FROM sessions WHERE workspace_id = ? AND alias = ?")
      .all(workspaceId, ref) as Array<{ id: string }>;
    if (aliased.length === 1) return { id: aliased[0]!.id };
    if (aliased.length > 1) return { ambiguous: aliased.map((r) => r.id) };
    // Fall back to id prefix (UUIDs are long; operators type the first 8).
    const prefixed = this.db
      .prepare("SELECT id FROM sessions WHERE workspace_id = ? AND id LIKE ?")
      .all(workspaceId, `${ref}%`) as Array<{ id: string }>;
    if (prefixed.length === 1) return { id: prefixed[0]!.id };
    if (prefixed.length > 1) return { ambiguous: prefixed.map((r) => r.id) };
    return null;
  }

  /** Set or clear the alias on a session. */
  setAlias(id: string, alias: string | null): void {
    this.db.prepare("UPDATE sessions SET alias = ? WHERE id = ?").run(alias, id);
  }

  get(id: string): SessionRecord | null {
    const row = this.db.prepare("SELECT * FROM sessions WHERE id = ?").get(id) as
      | SessionRow
      | undefined;
    return row ? rowToSession(row) : null;
  }

  listForWorkspace(workspaceId: string, opts: { openOnly?: boolean } = {}): SessionRecord[] {
    const rows = opts.openOnly
      ? (this.db
          .prepare(
            "SELECT * FROM sessions WHERE workspace_id = ? AND state = 'open' ORDER BY opened_at DESC",
          )
          .all(workspaceId) as SessionRow[])
      : (this.db
          .prepare("SELECT * FROM sessions WHERE workspace_id = ? ORDER BY opened_at DESC")
          .all(workspaceId) as SessionRow[]);
    return rows.map(rowToSession);
  }

  close(id: string, state: "closed" | "error" = "closed"): void {
    this.db
      .prepare("UPDATE sessions SET state=?, closed_at=datetime('now') WHERE id=?")
      .run(state, id);
  }

  update(id: string, patch: Partial<SessionRecord>): void {
    const existing = this.get(id);
    if (!existing) return;
    const merged = { ...existing, ...patch };
    this.db
      .prepare(
        `UPDATE sessions SET tunnel_peer=?, tunnel_local=?, description=?, metadata_json=?
         WHERE id=?`,
      )
      .run(
        merged.tunnelPeer ?? null,
        merged.tunnelLocal ?? null,
        merged.description ?? null,
        JSON.stringify(merged.metadata ?? {}),
        id,
      );
  }
}

interface SessionRow {
  id: string;
  workspace_id: string;
  host_id: string | null;
  service_id: string | null;
  kind: string;
  state: SessionRecord["state"];
  tunnel_peer: string | null;
  tunnel_local: string | null;
  alias: string | null;
  description: string | null;
  via_module: string | null;
  via_tool: string | null;
  opened_at: string;
  closed_at: string | null;
  metadata_json: string;
}

function rowToSession(row: SessionRow): SessionRecord {
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    hostId: row.host_id,
    serviceId: row.service_id,
    kind: row.kind,
    state: row.state,
    tunnelPeer: row.tunnel_peer,
    tunnelLocal: row.tunnel_local,
    alias: row.alias ?? null,
    description: row.description,
    viaModule: row.via_module,
    viaTool: row.via_tool,
    openedAt: row.opened_at,
    closedAt: row.closed_at,
    metadata: safeJson(row.metadata_json, {}),
  };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function safeJson<T>(s: string | null, fallback: T): T {
  if (!s) return fallback;
  try {
    return JSON.parse(s) as T;
  } catch {
    return fallback;
  }
}
