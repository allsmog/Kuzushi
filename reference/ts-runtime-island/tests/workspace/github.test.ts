/**
 * GitHub PR-comment integration — renders a comment body from a workspace
 * and posts it to the GitHub Issues-comments endpoint (PRs reuse that URL).
 * Network is stubbed via a fetch override.
 */

import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it, vi } from "vitest";
import { migration100 } from "../../src/migrations/100_schema_reset.js";
import { migration101 } from "../../src/migrations/101_workspace_entities.js";
import { migration102 } from "../../src/migrations/102_session_aliases.js";
import { migration103 } from "../../src/migrations/103_schedules.js";
import { parsePrRef, postPrComment, renderGitHubComment } from "../../src/workspace/io/github.js";
import { WorkspaceManager } from "../../src/workspace/manager.js";

const tempDirs: string[] = [];

function mkWorkspace() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kz-gh-"));
  tempDirs.push(dir);
  const db = new Database(path.join(dir, "x.sqlite3"));
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migration100.up(db);
  migration101.up(db);
  migration102.up(db);
  migration103.up(db);
  const mgr = new WorkspaceManager(db);
  const ws = mgr.create("pr-test", []);
  return { mgr, wsId: ws.id };
}

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe("parsePrRef", () => {
  it.each([
    ["acme/kuzushi#42", { owner: "acme", repo: "kuzushi", number: 42 }],
    ["acme-corp/my-repo#1", { owner: "acme-corp", repo: "my-repo", number: 1 }],
  ])("parses %s", (raw, expected) => {
    expect(parsePrRef(raw)).toEqual(expected);
  });

  it.each(["", "no-slash", "acme/repo", "acme/repo#", "acme/repo#abc"])("rejects %s", (bad) => {
    expect(parsePrRef(bad)).toBeNull();
  });
});

describe("renderGitHubComment", () => {
  it("groups vulns by severity with CVE/CWE references", () => {
    const { mgr, wsId } = mkWorkspace();
    mgr.vulns.create({
      workspaceId: wsId,
      name: "sql-injection",
      severity: "high",
      references: [{ type: "CWE", value: "CWE-89" }],
      metadata: { location: "src/db.ts:12" },
    });
    mgr.vulns.create({
      workspaceId: wsId,
      name: "redos",
      severity: "medium",
      references: [{ type: "CVE", value: "CVE-2026-0042" }],
      metadata: { location: "src/util.ts:55" },
    });
    const body = renderGitHubComment(mgr, wsId);
    expect(body).toContain("🔐 Kuzushi scan");
    expect(body).toContain("pr-test");
    expect(body).toContain("**high**: 1");
    expect(body).toContain("**medium**: 1");
    expect(body).toContain("### HIGH · 1");
    expect(body).toContain("### MEDIUM · 1");
    expect(body).toContain("CWE:CWE-89");
    expect(body).toContain("CVE:CVE-2026-0042");
    expect(body).toContain("src/db.ts:12");
  });

  it("renders an empty-findings summary", () => {
    const { mgr, wsId } = mkWorkspace();
    const body = renderGitHubComment(mgr, wsId);
    expect(body).toContain("_No findings._");
  });

  it("hides below-threshold severities when minSeverity is raised", () => {
    const { mgr, wsId } = mkWorkspace();
    mgr.vulns.create({ workspaceId: wsId, name: "noisy", severity: "info", references: [] });
    mgr.vulns.create({ workspaceId: wsId, name: "real", severity: "high", references: [] });
    const body = renderGitHubComment(mgr, wsId, { minSeverity: "high" });
    expect(body).toContain("real");
    expect(body).not.toContain("noisy");
    expect(body).not.toContain("INFO");
  });

  it("truncates long groups with a '…and N more' row", () => {
    const { mgr, wsId } = mkWorkspace();
    for (let i = 0; i < 30; i++) {
      mgr.vulns.create({
        workspaceId: wsId,
        name: `finding-${i}`,
        severity: "low",
        references: [],
      });
    }
    const body = renderGitHubComment(mgr, wsId, { maxPerGroup: 5 });
    expect(body).toContain("finding-0");
    expect(body).toContain("finding-4");
    expect(body).not.toContain("finding-5");
    expect(body).toContain("_…and 25 more_");
  });
});

describe("postPrComment", () => {
  it("dry-run returns body without POSTing", async () => {
    const result = await postPrComment({ owner: "a", repo: "b", number: 1 }, "hello", {
      dryRun: true,
    });
    expect(result.posted).toBe(false);
    expect(result.body).toBe("hello");
    expect(result.warning).toContain("dry-run");
  });

  it("skips without a token", async () => {
    const prior = process.env.GITHUB_TOKEN;
    delete process.env.GITHUB_TOKEN;
    try {
      const result = await postPrComment({ owner: "a", repo: "b", number: 1 }, "x");
      expect(result.posted).toBe(false);
      expect(result.warning).toContain("GITHUB_TOKEN");
    } finally {
      if (prior) process.env.GITHUB_TOKEN = prior;
    }
  });

  it("POSTs to the issues/{n}/comments URL when a token is present", async () => {
    const fetchImpl = vi.fn(async () => ({
      ok: true,
      status: 201,
      json: async () => ({ html_url: "https://github.com/x/y/issues/42#comment-5" }),
      text: async () => "",
    })) as unknown as typeof fetch;
    const result = await postPrComment({ owner: "acme", repo: "kuzushi", number: 42 }, "hello", {
      token: "ghp_fake",
      fetchImpl,
    });
    expect(result.posted).toBe(true);
    expect(result.url).toBe("https://github.com/x/y/issues/42#comment-5");
    const [url, init] = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("https://api.github.com/repos/acme/kuzushi/issues/42/comments");
    const headers = (init as { headers: Record<string, string> }).headers;
    expect(headers.Authorization).toBe("Bearer ghp_fake");
    const body = JSON.parse((init as { body: string }).body);
    expect(body.body).toBe("hello");
  });

  it("surfaces the status code on a non-2xx response", async () => {
    const fetchImpl = vi.fn(async () => ({
      ok: false,
      status: 403,
      json: async () => ({}),
      text: async () => "forbidden",
    })) as unknown as typeof fetch;
    const result = await postPrComment({ owner: "a", repo: "b", number: 1 }, "x", {
      token: "t",
      fetchImpl,
    });
    expect(result.posted).toBe(false);
    expect(result.warning).toContain("403");
    expect(result.warning).toContain("forbidden");
  });
});
