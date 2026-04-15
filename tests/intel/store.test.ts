import { afterEach, describe, expect, it } from "vitest";
import os from "node:os";
import path from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import Database from "better-sqlite3";
import { createIntelTables, SqliteIntelStore } from "../../src/intel/store.js";

const tempDirs: string[] = [];

function createTestStore(): SqliteIntelStore {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-intel-test-"));
  tempDirs.push(dir);
  const db = new Database(path.join(dir, "intel.sqlite3"));
  db.pragma("journal_mode = WAL");
  createIntelTables(db);
  return new SqliteIntelStore(db);
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("SqliteIntelStore", () => {
  it("ingests and retrieves documents", () => {
    const store = createTestStore();

    const id = store.ingest({
      source: "nvd",
      title: "CVE-2024-1234",
      content: "A critical SQL injection vulnerability in the login endpoint allows remote code execution.",
      metadata: { severity: "critical", cwe: "CWE-89" },
    });

    const doc = store.get(id);
    expect(doc).not.toBeNull();
    expect(doc!.title).toBe("CVE-2024-1234");
    expect(doc!.source).toBe("nvd");
    expect(doc!.metadata.severity).toBe("critical");
  });

  it("searches documents with FTS5", () => {
    const store = createTestStore();

    store.ingest({
      source: "nvd",
      title: "CVE-2024-1234",
      content: "SQL injection in login endpoint allows remote code execution via crafted username parameter.",
      metadata: { severity: "critical" },
    });

    store.ingest({
      source: "nvd",
      title: "CVE-2024-5678",
      content: "Cross-site scripting vulnerability in comment rendering allows stored XSS attacks.",
      metadata: { severity: "high" },
    });

    store.ingest({
      source: "attack",
      title: "T1190 Exploit Public-Facing Application",
      content: "Adversaries may exploit vulnerabilities in internet-facing applications to gain access.",
      metadata: { tactic: "initial-access" },
    });

    const sqlResults = store.search("SQL injection");
    expect(sqlResults.length).toBeGreaterThanOrEqual(1);
    expect(sqlResults[0]!.document.title).toBe("CVE-2024-1234");

    const xssResults = store.search("XSS");
    expect(xssResults.length).toBeGreaterThanOrEqual(1);
    expect(xssResults[0]!.document.title).toBe("CVE-2024-5678");
  });

  it("filters search by source", () => {
    const store = createTestStore();

    store.ingest({
      source: "nvd",
      title: "CVE-NVD",
      content: "A vulnerability in the application layer.",
      metadata: {},
    });

    store.ingest({
      source: "attack",
      title: "T1190",
      content: "Exploit vulnerability in application.",
      metadata: {},
    });

    const nvdOnly = store.search("vulnerability", { sources: ["nvd"] });
    expect(nvdOnly).toHaveLength(1);
    expect(nvdOnly[0]!.document.source).toBe("nvd");
  });

  it("batch ingests documents", () => {
    const store = createTestStore();

    const count = store.ingestBatch([
      { source: "cwe", title: "CWE-79", content: "Cross-site Scripting", metadata: {} },
      { source: "cwe", title: "CWE-89", content: "SQL Injection", metadata: {} },
      { source: "cwe", title: "CWE-78", content: "OS Command Injection", metadata: {} },
    ]);

    expect(count).toBe(3);
    expect(store.count("cwe")).toBe(3);
    expect(store.count()).toBe(3);
  });

  it("deletes documents and clears sources", () => {
    const store = createTestStore();

    const id = store.ingest({
      source: "custom",
      title: "Internal Policy",
      content: "All uploads must be scanned for malware.",
      metadata: {},
    });

    expect(store.delete(id)).toBe(true);
    expect(store.get(id)).toBeNull();
    expect(store.delete("nonexistent")).toBe(false);

    store.ingestBatch([
      { source: "findings", title: "F1", content: "SSRF in webhook", metadata: {} },
      { source: "findings", title: "F2", content: "IDOR in users", metadata: {} },
    ]);

    expect(store.clearSource("findings")).toBe(2);
    expect(store.count("findings")).toBe(0);
  });
});
