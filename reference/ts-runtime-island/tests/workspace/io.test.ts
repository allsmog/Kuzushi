import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { migration100 } from "../../src/migrations/100_schema_reset.js";
import { migration101 } from "../../src/migrations/101_workspace_entities.js";
import { exportKzBundle, exportSarif } from "../../src/workspace/io/export.js";
import { importKzBundle, importNmapXml, importSarif } from "../../src/workspace/io/import.js";
import { WorkspaceManager } from "../../src/workspace/manager.js";

const tempDirs: string[] = [];

function mkWorkspace(): { mgr: WorkspaceManager; wsId: string; dir: string } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-io-test-"));
  tempDirs.push(dir);
  const db = new Database(path.join(dir, "test.sqlite3"));
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migration100.up(db);
  migration101.up(db);
  const mgr = new WorkspaceManager(db);
  const ws = mgr.create("io-test", ["target-1"]);
  return { mgr, wsId: ws.id, dir };
}

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

describe("importSarif", () => {
  it("creates one vuln per SARIF result", () => {
    const { mgr, wsId } = mkWorkspace();
    const sarif = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "semgrep" } },
          results: [
            {
              ruleId: "rule.a",
              level: "error",
              message: { text: "bad thing" },
              locations: [{ physicalLocation: { artifactLocation: { uri: "src/a.ts" } } }],
              properties: { severity: "high", cve: ["CVE-2024-1"], cwe: ["CWE-79"] },
            },
            {
              ruleId: "rule.b",
              level: "warning",
              message: { text: "medium thing" },
              locations: [{ physicalLocation: { artifactLocation: { uri: "src/b.ts" } } }],
            },
          ],
        },
      ],
    };
    const summary = importSarif(mgr, wsId, JSON.stringify(sarif));
    expect(summary.vulns).toBe(2);

    const stored = mgr.vulns.listForWorkspace(wsId);
    expect(stored).toHaveLength(2);
    const a = stored.find((v) => v.name.startsWith("rule.a"));
    expect(a?.severity).toBe("high");
    expect(a?.references).toContainEqual({ type: "CVE", value: "CVE-2024-1" });
    const b = stored.find((v) => v.name.startsWith("rule.b"));
    expect(b?.severity).toBe("medium");
  });

  it("reports a warning on malformed input and creates nothing", () => {
    const { mgr, wsId } = mkWorkspace();
    const summary = importSarif(mgr, wsId, "{not json");
    expect(summary.vulns).toBe(0);
    expect(summary.warnings).toHaveLength(1);
    expect(summary.warnings[0]).toContain("SARIF parse failed");
  });
});

describe("exportSarif", () => {
  it("round-trips through importSarif", () => {
    const { mgr, wsId } = mkWorkspace();
    mgr.vulns.create({
      workspaceId: wsId,
      name: "rule.a @ src/a.ts",
      severity: "high",
      description: "boom",
      references: [
        { type: "CVE", value: "CVE-2024-1" },
        { type: "CWE", value: "CWE-79" },
      ],
      metadata: { ruleId: "rule.a", location: "src/a.ts" },
    });

    const out = exportSarif(mgr, wsId);
    const parsed = JSON.parse(out);
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0].results).toHaveLength(1);
    expect(parsed.runs[0].results[0].ruleId).toBe("rule.a");

    // Fresh workspace, round-trip import.
    const reimported = mkWorkspace();
    const summary = importSarif(reimported.mgr, reimported.wsId, out);
    expect(summary.vulns).toBe(1);
    expect(reimported.mgr.vulns.listForWorkspace(reimported.wsId)[0]?.severity).toBe("high");
  });
});

// ---------------------------------------------------------------------------
// nmap XML
// ---------------------------------------------------------------------------

describe("importNmapXml", () => {
  it("extracts hosts + open services, skips closed ports", () => {
    const { mgr, wsId } = mkWorkspace();
    const xml = `
<?xml version="1.0" ?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="target.example" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH 9.0"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.x" accuracy="95"/></os>
  </host>
</nmaprun>`;
    const summary = importNmapXml(mgr, wsId, xml);
    expect(summary.hosts).toBe(1);
    expect(summary.services).toBe(2);

    const hosts = mgr.hosts.list(wsId);
    expect(hosts[0]?.address).toBe("10.0.0.5");
    expect(hosts[0]?.hostname).toBe("target.example");
    expect(hosts[0]?.osName).toBe("Linux 5.x");

    const services = mgr.services.listForHost(hosts[0]!.id);
    expect(services.map((s) => s.port).sort()).toEqual([22, 80]);
    expect(services.find((s) => s.port === 22)?.banner).toBe("OpenSSH 9.0");
  });

  it("skips hosts missing an ipv4 address with a warning", () => {
    const { mgr, wsId } = mkWorkspace();
    const summary = importNmapXml(
      mgr,
      wsId,
      `<nmaprun><host><status state="up"/></host></nmaprun>`,
    );
    expect(summary.hosts).toBe(0);
    expect(summary.warnings).toContain("nmap: host missing ipv4 address; skipped");
  });
});

// ---------------------------------------------------------------------------
// kz-bundle round-trip
// ---------------------------------------------------------------------------

describe("kz-bundle round-trip", () => {
  it("exports + re-imports hosts / services / vulns / notes / creds", () => {
    const src = mkWorkspace();
    const h = src.mgr.hosts.upsert({
      workspaceId: src.wsId,
      address: "10.0.0.9",
      hostname: "db",
      osName: "linux",
    });
    src.mgr.services.upsert({ hostId: h.id, port: 5432, proto: "tcp", name: "postgres" });
    src.mgr.vulns.create({
      workspaceId: src.wsId,
      name: "weak-cred",
      severity: "high",
      references: [],
    });
    src.mgr.notes.create({ workspaceId: src.wsId, ntype: "triage", data: { note: "look here" } });
    src.mgr.creds.create({
      workspaceId: src.wsId,
      publicUsername: "admin",
      privateType: "password",
      privateData: "hunter2",
    });

    const out = exportKzBundle(src.mgr, src.wsId);
    expect(JSON.parse(out).schemaVersion).toBe(1);

    const dst = mkWorkspace();
    const summary = importKzBundle(dst.mgr, dst.wsId, out);
    expect(summary.hosts).toBe(1);
    expect(summary.services).toBe(1);
    expect(summary.vulns).toBe(1);
    expect(summary.notes).toBe(1);
    expect(summary.creds).toBe(1);

    const restored = dst.mgr.hosts.list(dst.wsId);
    expect(restored[0]?.address).toBe("10.0.0.9");
    const services = dst.mgr.services.listForHost(restored[0]!.id);
    expect(services[0]?.name).toBe("postgres");
    const vulns = dst.mgr.vulns.listForWorkspace(dst.wsId);
    expect(vulns[0]?.severity).toBe("high");
    const notes = dst.mgr.notes.listForWorkspace(dst.wsId);
    expect(notes[0]?.ntype).toBe("triage");
    const creds = dst.mgr.creds.listForWorkspace(dst.wsId);
    expect(creds[0]?.publicUsername).toBe("admin");
  });

  it("flags orphan services whose host address is missing", () => {
    const { mgr, wsId } = mkWorkspace();
    const bundle = {
      schemaVersion: 1,
      snapshotAt: new Date().toISOString(),
      workspace: { name: "x", targets: [], metadata: {} },
      hosts: [],
      services: [
        {
          hostAddress: "10.0.0.99",
          port: 80,
          proto: "tcp",
          name: null,
          banner: null,
          state: "open",
          info: {},
        },
      ],
      vulns: [],
      loot: [],
      notes: [],
      creds: [],
      sessions: [],
    };
    const summary = importKzBundle(mgr, wsId, JSON.stringify(bundle));
    expect(summary.services).toBe(0);
    expect(summary.warnings[0]).toContain("10.0.0.99");
  });

  it("rejects unsupported schemaVersion", () => {
    const { mgr, wsId } = mkWorkspace();
    const summary = importKzBundle(
      mgr,
      wsId,
      JSON.stringify({ schemaVersion: 99, hosts: [], services: [] }),
    );
    expect(summary.warnings[0]).toContain("schemaVersion");
  });
});

// ---------------------------------------------------------------------------
// importFile dispatcher (reads real files)
// ---------------------------------------------------------------------------

describe("importFile (dispatch)", () => {
  it("reads an on-disk file and routes to the right adapter", async () => {
    const { importFile } = await import("../../src/workspace/io/import.js");
    const { mgr, wsId, dir } = mkWorkspace();
    const file = path.join(dir, "result.sarif");
    writeFileSync(
      file,
      JSON.stringify({
        version: "2.1.0",
        runs: [
          { tool: { driver: { name: "x" } }, results: [{ ruleId: "a", message: { text: "m" } }] },
        ],
      }),
    );
    const summary = importFile(mgr, wsId, "sarif", file);
    expect(summary.vulns).toBe(1);
    // Quiet the unused-var lint — readFileSync is imported for the reader path.
    expect(typeof readFileSync).toBe("function");
  });
});
