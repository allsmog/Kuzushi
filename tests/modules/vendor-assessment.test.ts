import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  attachDocument,
  inferDocumentKind,
} from "../../src/modules/vendor-assessment/documents.js";
import { createVendorAssessmentModule } from "../../src/modules/vendor-assessment/vendor-assessment.js";
import { createFakeRuntime, createMockToolContext } from "../../src/testing/index.js";

const tempDirs: string[] = [];

function tempRoot(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "vendor-assessment-"));
  tempDirs.push(dir);
  return dir;
}

function tool(name: string) {
  const found = createVendorAssessmentModule().tools.find((candidate) => candidate.name === name);
  if (!found) throw new Error(`missing tool ${name}`);
  return found;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("vendor assessment module", () => {
  it("infers document kind from source names and explicit overrides", () => {
    expect(inferDocumentKind("security-questionnaire.pdf")).toBe("questionnaire");
    expect(inferDocumentKind("architecture-flow.png")).toBe("diagram");
    expect(inferDocumentKind("meeting-notes.md")).toBe("transcript");
    expect(inferDocumentKind("anything.txt", "contract")).toBe("contract");
  });

  it("parses local text documents during attachment", () => {
    const root = tempRoot();
    const file = path.join(root, "questionnaire.md");
    writeFileSync(file, "Use case: internal assistant\nIntegration: Calendar via OAuth\n");

    const doc = attachDocument({ source: file, cwd: root });

    expect(doc.kind).toBe("questionnaire");
    expect(doc.status).toBe("parsed");
    expect(doc.extracted?.text).toContain("Calendar via OAuth");
  });

  it("persists draft scope via attach and clears it via scope", async () => {
    const root = tempRoot();
    const file = path.join(root, "questionnaire.md");
    writeFileSync(file, "Use case: support workflow\nIntegration: CRM via OAuth\n");
    const ctx = createMockToolContext({ cwd: root, target: root });

    const attach = await tool("vendor-assessment:attach").execute(
      { source: file, vendorName: "Vendor One", integrations: ["CRM"] },
      ctx,
    );
    expect(attach.ok).toBe(true);
    expect(existsSync(path.join(root, ".kuzushi/vendor-assessment/scope.draft.json"))).toBe(true);

    const shown = await tool("vendor-assessment:scope").execute({}, ctx);
    expect(shown.output).toContain("Vendor One");
    expect(shown.output).toContain("questionnaire.md");

    const cleared = await tool("vendor-assessment:scope").execute({ clear: true }, ctx);
    expect(cleared.ok).toBe(true);
    expect(existsSync(path.join(root, ".kuzushi/vendor-assessment/scope.draft.json"))).toBe(false);
  });

  it("keeps positional attach file paths out of the artifact root", async () => {
    const root = tempRoot();
    const file = path.join(root, "questionnaire.md");
    writeFileSync(file, "Use case: support workflow\nIntegration: CRM via OAuth\n");
    const ctx = createMockToolContext({ cwd: root, target: file });

    const attach = await tool("vendor-assessment:attach").execute({ target: file }, ctx);

    expect(attach.ok).toBe(true);
    expect(existsSync(path.join(root, ".kuzushi/vendor-assessment/scope.draft.json"))).toBe(true);
    expect(existsSync(path.join(file, ".kuzushi/vendor-assessment/scope.draft.json"))).toBe(false);
  });

  it("generates an intake report when no meaningful documents exist", async () => {
    const root = tempRoot();
    const ctx = createMockToolContext({ cwd: root, target: root });

    const result = await tool("vendor-assessment:assess").execute(
      { vendorName: "Vendor One" },
      ctx,
    );

    expect(result.ok).toBe(true);
    const data = result.data as { report: { mode: string; artifacts: { reportPath: string } } };
    expect(data.report.mode).toBe("intake");
    expect(existsSync(data.report.artifacts.reportPath)).toBe(true);
    expect(readFileSync(data.report.artifacts.reportPath, "utf-8")).toContain(
      "Vendor AI Security Assessment Report",
    );
  });

  it("uses model report output for document-backed assessments and writes prompts", async () => {
    const root = tempRoot();
    const file = path.join(root, "questionnaire.md");
    writeFileSync(
      file,
      [
        "Use case: employee productivity assistant.",
        "Integration: Calendar via OAuth with read-only event metadata.",
        "The vendor stores access tokens in a managed secrets vault with rotation.",
      ].join("\n"),
    );
    const runtime = createFakeRuntime([
      {
        match: /Stage 7: Final Report/,
        output: [
          "# Vendor AI Security Assessment Report",
          "",
          "## Document Metadata",
          "Overall Risk Rating: Low",
          "",
          "## Appendix: Machine-readable summary",
          "```json",
          '{"overallRisk":"Low","criticalIntegrations":[]}',
          "```",
        ].join("\n"),
        costUsd: 0.12,
      },
    ]);
    const ctx = createMockToolContext({ cwd: root, target: root, runtime });
    await tool("vendor-assessment:attach").execute({ source: file }, ctx);

    const result = await tool("vendor-assessment:assess").execute(
      { vendorName: "Vendor One" },
      ctx,
    );

    expect(result.ok).toBe(true);
    const data = result.data as {
      report: { overallRisk: string; artifacts: { reportPath: string; promptsDir: string } };
    };
    expect(data.report.overallRisk).toBe("Low");
    expect(readFileSync(data.report.artifacts.reportPath, "utf-8")).toContain(
      "Overall Risk Rating: Low",
    );
    expect(existsSync(path.join(data.report.artifacts.promptsDir, "07-final-report.md"))).toBe(
      true,
    );
  });

  it("renders evidence-aware fallback reports when model output is malformed", async () => {
    const root = tempRoot();
    const file = path.join(root, "public-evidence.md");
    writeFileSync(
      file,
      [
        "# Public Evidence",
        "Scope: Acme Events handles attendee PII for event registration workflows.",
        "This packet does not include a private security questionnaire or architecture/data-flow diagram.",
        "The public security page lists SOC 2, ISO 27001, PCI-DSS Level 1, and GDPR posture.",
        "The Salesforce integration page says registrants sync to Salesforce and sync details include which API key was used.",
        "The Marketo integration page says setup uses Marketo API credentials.",
        "The HubSpot guide says setup involves entering HubSpot credentials and mapping fields.",
      ].join("\n"),
    );
    const runtime = createFakeRuntime([
      {
        match: /Stage 7: Final Report/,
        output: "malformed model output",
        costUsd: 0.01,
      },
    ]);
    const ctx = createMockToolContext({ cwd: root, target: root, runtime });
    await tool("vendor-assessment:attach").execute(
      {
        source: file,
        kind: "security-report",
        vendorName: "Acme Events",
        primaryDomain: "example.test",
        useCase: "event registration and management",
        dataClasses: ["attendee-pii"],
        integrations: ["Salesforce", "Marketo", "HubSpot"],
      },
      ctx,
    );

    const result = await tool("vendor-assessment:assess").execute({}, ctx);

    expect(result.ok).toBe(true);
    const data = result.data as {
      report: { overallRisk: string; artifacts: { reportPath: string } };
    };
    const markdown = readFileSync(data.report.artifacts.reportPath, "utf-8");
    expect(data.report.overallRisk).toBe("High");
    expect(markdown).toContain("Evidence Highlights");
    expect(markdown).toContain("SOC 2");
    expect(markdown).toContain("Salesforce integration page");
    expect(markdown).toContain("credential storage");
    expect(markdown).toContain("No security questionnaire was attached");
    expect(markdown).toContain("Generated fallback report");
    expect(markdown).not.toContain("Overall Risk Rating: Critical");
  });
});
