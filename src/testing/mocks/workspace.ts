/**
 * In-memory implementation of `WorkspaceHandle` for unit tests.
 *
 * Provides a minimal host/service/vuln/note store that records `upsert`
 * and `create` calls so tests can assert what a tool persisted without
 * spinning up a sqlite workspace.
 */

import type {
  WorkspaceHandle,
  WorkspaceHostStore,
  WorkspaceNoteStore,
  WorkspaceServiceStore,
  WorkspaceVulnStore,
} from "../../modules/host-handles.js";

export interface MockWorkspace extends WorkspaceHandle {
  /** Hosts observed via `hosts.upsert`. */
  readonly hostUpserts: object[];
  /** Services observed via `services.upsert`. */
  readonly serviceUpserts: object[];
  /** Notes observed via `notes.create`. */
  readonly noteCreates: object[];
  /** Pre-seeded vulns returned from `vulns.listForWorkspace`. */
  readonly vulnRows: unknown[];
  /** Add rows that `vulns.listForWorkspace` should return. */
  seedVulns(rows: unknown[]): void;
  /** Reset every recorded write + pre-seed. */
  clear(): void;
}

/**
 * Build a `WorkspaceHandle` stub with recording stores. Reads return empty
 * arrays by default; writes are captured on `.hostUpserts` / `.serviceUpserts`
 * / `.noteCreates`. Use `seedVulns()` to prime the vuln read path.
 *
 * @example
 *   const workspace = createMockWorkspace();
 *   workspace.seedVulns([{ id: 1, cve: "CVE-2024-0001" }]);
 *   const ctx = createMockToolContext({ workspace });
 *   await myVulnTool.execute({ workspaceId: "w1" }, ctx);
 *   expect(workspace.noteCreates).toHaveLength(1);
 */
export function createMockWorkspace(): MockWorkspace {
  const hostUpserts: object[] = [];
  const serviceUpserts: object[] = [];
  const noteCreates: object[] = [];
  let vulnRows: unknown[] = [];

  const hosts: WorkspaceHostStore = {
    upsert(input) {
      hostUpserts.push(input);
      return input;
    },
    findByAddress() {
      return undefined;
    },
  };

  const services: WorkspaceServiceStore = {
    upsert(input) {
      serviceUpserts.push(input);
      return input;
    },
  };

  const vulns: WorkspaceVulnStore = {
    listForWorkspace() {
      return vulnRows;
    },
  };

  const notes: WorkspaceNoteStore = {
    create(input) {
      noteCreates.push(input);
      return input;
    },
  };

  return {
    hosts,
    services,
    vulns,
    notes,
    hostUpserts,
    serviceUpserts,
    noteCreates,
    get vulnRows() {
      return vulnRows;
    },
    rawDb() {
      return undefined;
    },
    seedVulns(rows) {
      vulnRows = [...rows];
    },
    clear() {
      hostUpserts.length = 0;
      serviceUpserts.length = 0;
      noteCreates.length = 0;
      vulnRows = [];
    },
  };
}
