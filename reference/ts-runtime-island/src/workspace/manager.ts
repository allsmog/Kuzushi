import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import type { ContextSnapshot } from "../ui/state.js";
import {
  CredStore,
  HostStore,
  LootStore,
  NoteStore,
  ServiceStore,
  SessionStore,
  VulnStore,
} from "./entities.js";
import type { Workspace } from "./types.js";

/** Manages workspace CRUD and snapshot persistence via SQLite. */
export class WorkspaceManager {
  /** Host upsert + query (workspace-scoped). */
  readonly hosts: HostStore;
  /** Service upsert + query (host-scoped). */
  readonly services: ServiceStore;
  /** Vulnerability records. */
  readonly vulns: VulnStore;
  /** Extracted artifacts (files, screenshots, notes). */
  readonly loot: LootStore;
  /** Free-form typed observations. */
  readonly notes: NoteStore;
  /** Credentials (public/private/realm) + logins. */
  readonly creds: CredStore;
  /** Long-lived connections (ssh/browser/honeypot/agent). */
  readonly sessions: SessionStore;

  constructor(private readonly db: Database.Database) {
    this.hosts = new HostStore(db);
    this.services = new ServiceStore(db);
    this.vulns = new VulnStore(db);
    this.loot = new LootStore(db);
    this.notes = new NoteStore(db);
    this.creds = new CredStore(db);
    this.sessions = new SessionStore(db);
  }

  create(name: string, targets: string[] = []): Workspace {
    const id = randomUUID();
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO workspaces (id, name, targets_json, created_at, last_accessed_at, metadata_json)
       VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(id, name, JSON.stringify(targets), now, now, "{}");
    return { id, name, targets, createdAt: now, lastAccessedAt: now, metadata: {} };
  }

  get(id: string): Workspace | null {
    const row = this.db.prepare("SELECT * FROM workspaces WHERE id = ?").get(id) as
      | WorkspaceRow
      | undefined;
    return row ? rowToWorkspace(row) : null;
  }

  getByName(name: string): Workspace | null {
    const row = this.db.prepare("SELECT * FROM workspaces WHERE name = ?").get(name) as
      | WorkspaceRow
      | undefined;
    return row ? rowToWorkspace(row) : null;
  }

  getOrCreate(name: string, targets: string[] = []): Workspace {
    const existing = this.getByName(name);
    if (existing) return existing;
    return this.create(name, targets);
  }

  list(): Workspace[] {
    const rows = this.db
      .prepare("SELECT * FROM workspaces ORDER BY last_accessed_at DESC")
      .all() as WorkspaceRow[];
    return rows.map(rowToWorkspace);
  }

  update(id: string, partial: Partial<Pick<Workspace, "name" | "targets" | "metadata">>): void {
    const ws = this.get(id);
    if (!ws) return;

    const name = partial.name ?? ws.name;
    const targets = partial.targets ?? ws.targets;
    const metadata = partial.metadata ?? ws.metadata;
    const now = new Date().toISOString();

    this.db
      .prepare(
        `UPDATE workspaces SET name = ?, targets_json = ?, metadata_json = ?, updated_at = ?
       WHERE id = ?`,
      )
      .run(name, JSON.stringify(targets), JSON.stringify(metadata), now, id);
  }

  delete(id: string): void {
    this.db.prepare("DELETE FROM workspaces WHERE id = ?").run(id);
  }

  addTarget(id: string, target: string): void {
    const ws = this.get(id);
    if (!ws) return;
    if (ws.targets.includes(target)) return;
    this.update(id, { targets: [...ws.targets, target] });
  }

  touchAccessed(id: string): void {
    const now = new Date().toISOString();
    this.db.prepare("UPDATE workspaces SET last_accessed_at = ? WHERE id = ?").run(now, id);
  }

  saveSnapshot(workspaceId: string, snapshot: ContextSnapshot): void {
    this.db
      .prepare("INSERT INTO workspace_snapshots (workspace_id, snapshot_json) VALUES (?, ?)")
      .run(workspaceId, JSON.stringify(snapshot));
  }

  loadLatestSnapshot(workspaceId: string): ContextSnapshot | null {
    const row = this.db
      .prepare(
        "SELECT snapshot_json FROM workspace_snapshots WHERE workspace_id = ? ORDER BY id DESC LIMIT 1",
      )
      .get(workspaceId) as { snapshot_json: string } | undefined;
    if (!row) return null;
    try {
      return JSON.parse(row.snapshot_json) as ContextSnapshot;
    } catch {
      return null;
    }
  }

  /**
   * Internal escape hatch — returns the raw better-sqlite3 handle.
   *
   * Prefer the typed stores (`hosts`, `services`, `vulns`, ...) when
   * possible. This accessor exists for agent tools that delegate to
   * legacy DB-coupled functions (`runPatchPipeline`, `triageFindingsBatch`,
   * etc.) which take a `Database.Database` directly.
   */
  rawDb(): Database.Database {
    return this.db;
  }
}

interface WorkspaceRow {
  id: string;
  name: string;
  targets_json: string;
  created_at: string;
  last_accessed_at: string;
  metadata_json: string;
}

function rowToWorkspace(row: WorkspaceRow): Workspace {
  return {
    id: row.id,
    name: row.name,
    targets: safeParseArray(row.targets_json),
    createdAt: row.created_at,
    lastAccessedAt: row.last_accessed_at,
    metadata: safeParseObject(row.metadata_json),
  };
}

function safeParseArray(json: string): string[] {
  try {
    const parsed = JSON.parse(json);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function safeParseObject(json: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}
