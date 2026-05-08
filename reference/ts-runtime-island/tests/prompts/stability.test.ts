import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { renderTemplate } from "../../src/prompts/template.js";

function hashString(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

// A representative template with conditionals, loops, and substitution
const STABILITY_TEMPLATE = `You are a security analyst.

{% if repoContext %}
Repository: {{ repoName }}
Languages: {{ repoContext.languages | join(", ") }}
Frameworks: {{ repoContext.frameworks | join(", ") }}
{% endif %}

{% if findings %}
## Findings

{% for finding in findings %}
### Finding {{ loop.index }}: {{ finding.ruleId }}
- File: {{ finding.filePath }}:{{ finding.startLine }}
- Severity: {{ finding.severity }}
- Message: {{ finding.message }}
{% endfor %}
{% endif %}

{% if not skipInstructions %}
## Instructions

Analyze each finding and produce a verdict.
{% endif %}

{% if mode == "strict" %}
Use strict analysis mode.
{% elif mode == "relaxed" %}
Use relaxed analysis mode.
{% else %}
Use default analysis mode.
{% endif %}`;

const STABILITY_CONTEXT = {
  repoName: "test-repo",
  repoContext: {
    languages: ["TypeScript", "JavaScript", "Python"],
    frameworks: ["Express", "React", "FastAPI"],
  },
  findings: [
    {
      ruleId: "sql-injection",
      filePath: "src/db.ts",
      startLine: 42,
      severity: "HIGH",
      message: "Possible SQL injection via user input",
    },
    {
      ruleId: "xss-reflected",
      filePath: "src/api/handler.ts",
      startLine: 15,
      severity: "MEDIUM",
      message: "Reflected XSS in query parameter",
    },
    {
      ruleId: "path-traversal",
      filePath: "src/files/upload.ts",
      startLine: 88,
      severity: "HIGH",
      message: "Path traversal via filename parameter",
    },
  ],
  skipInstructions: false,
  mode: "strict",
};

describe("Prompt Stability", () => {
  it("renders the same output across 10 sequential calls", () => {
    const results: string[] = [];
    for (let i = 0; i < 10; i++) {
      results.push(renderTemplate(STABILITY_TEMPLATE, STABILITY_CONTEXT));
    }

    const first = results[0];
    for (let i = 1; i < results.length; i++) {
      expect(results[i]).toBe(first);
    }
  });

  it("produces identical hashes across 10 sequential renders", () => {
    const hashes = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const rendered = renderTemplate(STABILITY_TEMPLATE, STABILITY_CONTEXT);
      hashes.add(hashString(rendered));
    }

    expect(hashes.size).toBe(1);
  });

  it("renders identically under concurrent execution (20 parallel)", async () => {
    const promises = Array.from({ length: 20 }, () =>
      Promise.resolve(renderTemplate(STABILITY_TEMPLATE, STABILITY_CONTEXT)),
    );

    const results = await Promise.all(promises);
    const first = results[0];
    for (const result of results) {
      expect(result).toBe(first);
    }
  });

  it("produces identical hashes under concurrent execution", async () => {
    const promises = Array.from({ length: 20 }, () =>
      Promise.resolve(hashString(renderTemplate(STABILITY_TEMPLATE, STABILITY_CONTEXT))),
    );

    const hashes = await Promise.all(promises);
    const unique = new Set(hashes);
    expect(unique.size).toBe(1);
  });

  it("is stable with different context modes", () => {
    const modes = ["strict", "relaxed", "default"];

    for (const mode of modes) {
      const ctx = { ...STABILITY_CONTEXT, mode };
      const results: string[] = [];
      for (let i = 0; i < 5; i++) {
        results.push(renderTemplate(STABILITY_TEMPLATE, ctx));
      }

      const first = results[0];
      for (const result of results) {
        expect(result).toBe(first);
      }
    }
  });

  it("is stable with empty/missing optional context", () => {
    const minimalContext = {
      repoName: "minimal-repo",
      skipInstructions: true,
      mode: "default",
    };

    const results: string[] = [];
    for (let i = 0; i < 10; i++) {
      results.push(renderTemplate(STABILITY_TEMPLATE, minimalContext));
    }

    const first = results[0];
    for (const result of results) {
      expect(result).toBe(first);
    }
  });

  it("preserves deterministic ordering of modules in composed prompts", () => {
    // Simple template that exercises ordering
    const template = `{% for item in items %}{{ item }}{% endfor %}`;
    const items = ["alpha", "beta", "gamma", "delta", "epsilon"];

    const results: string[] = [];
    for (let i = 0; i < 10; i++) {
      results.push(renderTemplate(template, { items }));
    }

    const first = results[0];
    expect(first).toBe("alphabetagammadeltaepsilon");
    for (const result of results) {
      expect(result).toBe(first);
    }
  });
});
