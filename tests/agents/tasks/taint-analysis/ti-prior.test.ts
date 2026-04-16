import { afterEach, describe, expect, it, vi } from "vitest";
import { buildTiPriorArtifacts } from "../../../../src/agents/tasks/taint-analysis/ti-prior.js";
import { TAINT_ANALYSIS_PASSES } from "../../../../src/agents/tasks/taint-analysis/types.js";

interface MockResponse {
  ok: boolean;
  status: number;
  statusText: string;
  json(): Promise<unknown>;
}

function jsonResponse(payload: unknown): MockResponse {
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    async json() {
      return payload;
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("buildTiPriorArtifacts", () => {
  it("builds TI prior with live references and high TI weight when KEV evidence exists", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("known_exploited_vulnerabilities.json")) {
          return jsonResponse({
            vulnerabilities: [
              {
                cveID: "CVE-2024-12345",
                cwes: "CWE-22",
                shortDescription: "Path traversal in archive extraction",
              },
            ],
          });
        }

        if (url.includes("cweId=CWE-22")) {
          return jsonResponse({
            vulnerabilities: [
              {
                cve: {
                  id: "CVE-2023-99999",
                  descriptions: [{ lang: "en", value: "Arbitrary file read via traversal." }],
                  weaknesses: [{ description: [{ value: "CWE-22" }] }],
                },
              },
            ],
          });
        }

        return jsonResponse({ vulnerabilities: [] });
      }),
    );

    const { document, markdown } = await buildTiPriorArtifacts({
      passes: [TAINT_ANALYSIS_PASSES[0]],
      timeoutMs: 5_000,
    });

    const cwe22 = document.cwes.find((entry) => entry.cwe === "CWE-22");
    expect(document.degraded).toBe(false);
    expect(cwe22).toBeDefined();
    expect(cwe22?.tiWeight).toBe("HIGH");
    expect(cwe22?.references.some((ref) => ref.id === "CVE-2024-12345")).toBe(true);
    expect(markdown).toContain("CWE-22");
    expect(markdown).toContain("CVE-2024-12345");
  });

  it("marks TI prior as degraded when live fetch fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network unavailable");
      }),
    );

    const { document, markdown } = await buildTiPriorArtifacts({
      passes: [TAINT_ANALYSIS_PASSES[0]],
      timeoutMs: 5_000,
    });

    expect(document.degraded).toBe(true);
    expect(document.errors.length).toBeGreaterThan(0);
    expect(markdown).toContain("Fetch Issues");
  });
});
