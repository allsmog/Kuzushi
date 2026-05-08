/**
 * In-process session manager — tracks long-lived connection handles
 * (SSH, browser, honeypot monitor, agent) alongside their DB record.
 *
 * Inspired by Msf::SessionManager (lib/msf/core/session_manager.rb), minus the
 * Meterpreter-specific polling. The DB record (SessionStore) is the durable
 * truth; this manager holds the live handles that can't survive a restart.
 */

import { EventEmitter } from "node:events";
import type { PrintSink } from "../copilot/print.js";
import { toErrorMessage } from "../utils.js";
import type { SessionInsert, SessionRecord, SessionStore } from "../workspace/entities.js";
export interface SessionHandle {
  /** DB row mirror — updated when metadata changes. */
  record: SessionRecord;
  /**
   * Close the live handle. Caller is responsible for flushing/cleanup; the
   * manager will update the DB state to 'closed' afterwards.
   */
  close(): Promise<void> | void;
  /**
   * Optional interact — write a line of input, return output. Individual kinds
   * (shell/ssh/browser) decide how to map this to their protocol.
   */
  interact?(input: string, signal?: AbortSignal): Promise<string>;
}

export interface SessionEvents {
  "session:open": (record: SessionRecord) => void;
  "session:close": (record: SessionRecord, reason: "closed" | "error") => void;
}

export class SessionManager extends EventEmitter {
  private readonly live = new Map<string, SessionHandle>();

  constructor(
    private readonly store: SessionStore,
    private readonly print?: PrintSink,
  ) {
    super();
  }

  /** Open a new session: persist a DB record and register the live handle. */
  open(
    input: SessionInsert,
    factory: (record: SessionRecord) => SessionHandle | Promise<SessionHandle>,
  ): Promise<SessionRecord>;
  open(input: SessionInsert): Promise<SessionRecord>;
  async open(
    input: SessionInsert,
    factory?: (record: SessionRecord) => SessionHandle | Promise<SessionHandle>,
  ): Promise<SessionRecord> {
    const record = this.store.create(input);
    if (factory) {
      const handle = await factory(record);
      this.live.set(record.id, handle);
    }
    this.print?.good(`Session ${record.id.slice(0, 8)} (${record.kind}) opened`);
    this.emit("session:open", record);
    return record;
  }

  /** Close a session: invoke handle.close() if live, then mark DB state. */
  async close(id: string, reason: "closed" | "error" = "closed"): Promise<void> {
    const handle = this.live.get(id);
    this.live.delete(id);
    if (handle) {
      try {
        await handle.close();
      } catch (err) {
        this.print?.warn(`Session ${id.slice(0, 8)} close error: ${toErrorMessage(err)}`);
      }
    }
    this.store.close(id, reason);
    const record = this.store.get(id);
    if (record) {
      this.emit("session:close", record, reason);
      this.print?.status(`Session ${record.id.slice(0, 8)} ${reason}`);
    }
  }

  /** Live handle lookup (post-open). */
  getLive(id: string): SessionHandle | undefined {
    return this.live.get(id);
  }

  /** All live sessions for a workspace. */
  liveForWorkspace(workspaceId: string): SessionHandle[] {
    return [...this.live.values()].filter((h) => h.record.workspaceId === workspaceId);
  }

  /** Close every live session (shell exit). */
  async closeAll(reason: "closed" | "error" = "closed"): Promise<void> {
    for (const id of [...this.live.keys()]) {
      await this.close(id, reason);
    }
  }
}
