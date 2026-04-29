/**
 * dep-hygiene module — flag risky dependency-version specifiers across
 * common manifest formats (package.json, pyproject.toml, Cargo.toml, go.mod).
 *
 * Pure shell-side tool — does not require an active scan pipeline.
 */

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { defineModule, defineTool } from "../define.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";

interface DepFinding {
  manifest: "package.json" | "pyproject.toml" | "Cargo.toml" | "go.mod";
  filePath: string;
  packageName: string;
  rawConstraint: string;
  severity: "low" | "medium" | "high";
  reason: string;
}

const TARGET_MANIFESTS = ["package.json", "pyproject.toml", "Cargo.toml", "go.mod"] as const;

export function createDepHygieneModule(): CopilotModule {
  const checkTool = defineTool<"dep-hygiene">({
    name: "dep-hygiene:check",
    displayName: "Check Dependencies",
    description:
      "Flag floor-only ranges, latest tags, and unpinned commits across npm/PyPI/Cargo/go.mod manifests.",
    headless: true,
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Repository root containing the manifest files (defaults to cwd).",
        },
      },
    },
    formatInput(input) {
      const t = (input as Record<string, unknown> | undefined)?.["target"];
      return typeof t === "string" ? t : null;
    },
    renderResult(result) {
      const data = result.data as { findings?: ReadonlyArray<DepFinding> } | undefined;
      const total = data?.findings?.length ?? 0;
      return total === 0
        ? "No risky dependency specifiers found."
        : `${total} risky dependency specifier${total === 1 ? "" : "s"} flagged.`;
    },
    async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
      const params = (input ?? {}) as Record<string, unknown>;
      const target =
        typeof params["target"] === "string"
          ? path.resolve((params["target"] as string).trim())
          : path.resolve(ctx.cwd);

      const findings: DepFinding[] = [];
      for (const manifestName of TARGET_MANIFESTS) {
        const manifestPath = path.join(target, manifestName);
        if (!existsSync(manifestPath)) continue;
        try {
          const raw = readFileSync(manifestPath, "utf8");
          findings.push(...analyzeManifest(manifestName, manifestPath, raw));
        } catch (err) {
          ctx.logger?.warn?.(
            `dep-hygiene: failed to read ${manifestPath}: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }

      if (findings.length === 0) {
        return {
          ok: true,
          output: `dep-hygiene: no risky specifiers found under ${target}.`,
          data: { count: 0, findings: [] },
        };
      }

      return {
        ok: true,
        output: formatFindings(findings, target),
        data: { count: findings.length, findings },
      };
    },
  });

  return defineModule({
    id: "dep-hygiene",
    displayName: "Dependency Hygiene",
    category: "defense",
    version: "0.21.0",
    description:
      "Flag risky dependency specifiers (latest tags, floor-only ranges, commit pins) across manifests.",
    rank: "good",
    notes: { stability: ["stable"], reliability: ["reliable"], sideEffects: [] },
    tools: [checkTool],
  });
}

export function analyzeManifest(
  manifestName: (typeof TARGET_MANIFESTS)[number],
  filePath: string,
  raw: string,
): DepFinding[] {
  switch (manifestName) {
    case "package.json":
      return analyzePackageJson(filePath, raw);
    case "pyproject.toml":
      return analyzePyprojectToml(filePath, raw);
    case "Cargo.toml":
      return analyzeCargoToml(filePath, raw);
    case "go.mod":
      return analyzeGoMod(filePath, raw);
  }
}

function analyzePackageJson(filePath: string, raw: string): DepFinding[] {
  let parsed: { dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown> };
  try {
    parsed = JSON.parse(raw) as typeof parsed;
  } catch {
    return [];
  }
  const out: DepFinding[] = [];
  for (const section of ["dependencies", "devDependencies"] as const) {
    const deps = parsed[section];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, value] of Object.entries(deps)) {
      if (typeof value !== "string") continue;
      const trimmed = value.trim();
      if (
        trimmed === "" ||
        trimmed === "*" ||
        trimmed === "latest" ||
        trimmed.endsWith("@latest")
      ) {
        out.push({
          manifest: "package.json",
          filePath,
          packageName: name,
          rawConstraint: value,
          severity: "high",
          reason: `${section}: floating tag — pulls whatever is published next, even a malicious release`,
        });
        continue;
      }
      if (/^>=?\s*\d/.test(trimmed) && !/[<,]/.test(trimmed)) {
        out.push({
          manifest: "package.json",
          filePath,
          packageName: name,
          rawConstraint: value,
          severity: "medium",
          reason: `${section}: floor-only range; declare an upper bound to prevent unintended major upgrades`,
        });
        continue;
      }
      if (/^\^0\./.test(trimmed)) {
        out.push({
          manifest: "package.json",
          filePath,
          packageName: name,
          rawConstraint: value,
          severity: "low",
          reason: `${section}: caret on 0.x — pre-1.0 packages can break under any release`,
        });
      }
    }
  }
  return out;
}

function analyzePyprojectToml(filePath: string, raw: string): DepFinding[] {
  const out: DepFinding[] = [];
  const lines = raw.split("\n");
  let inDeps = false;
  let inPoetryDeps = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("[")) {
      inDeps = trimmed === "[project]" || trimmed === "[project.optional-dependencies]";
      inPoetryDeps =
        trimmed === "[tool.poetry.dependencies]" || trimmed === "[tool.poetry.dev-dependencies]";
      continue;
    }
    if (inDeps) {
      const match = trimmed.match(/^"([^"]+)"\s*,?\s*$/);
      if (match) {
        const finding = analyzePep508(filePath, match[1]!);
        if (finding) out.push(finding);
      }
    }
    if (inPoetryDeps) {
      const eq = trimmed.indexOf("=");
      if (eq <= 0) continue;
      const name = trimmed.slice(0, eq).trim();
      const value = trimmed.slice(eq + 1).trim();
      if (value.startsWith("{")) continue;
      const constraint = value.replace(/^"|"$|,$/g, "").trim();
      if (constraint === "*" || constraint === "" || constraint.toLowerCase() === "latest") {
        out.push({
          manifest: "pyproject.toml",
          filePath,
          packageName: name,
          rawConstraint: constraint,
          severity: "high",
          reason: "poetry: wildcard pin — accepts any future release without review",
        });
      } else if (/^>=?\s*\d/.test(constraint) && !/<|,/.test(constraint)) {
        out.push({
          manifest: "pyproject.toml",
          filePath,
          packageName: name,
          rawConstraint: constraint,
          severity: "medium",
          reason: "poetry: floor-only range; add an upper bound to fix the supply-chain surface",
        });
      }
    }
  }
  return out;
}

function analyzePep508(filePath: string, spec: string): DepFinding | null {
  const cleaned = spec.split(";")[0]!.trim();
  const match = cleaned.match(/^([A-Za-z0-9_.-]+)\s*(.*)$/);
  if (!match) return null;
  const name = match[1]!;
  const constraint = (match[2] ?? "").trim();
  if (!constraint) {
    return {
      manifest: "pyproject.toml",
      filePath,
      packageName: name,
      rawConstraint: constraint,
      severity: "high",
      reason: "PEP 508: unconstrained — accepts any installed version, including malicious",
    };
  }
  if (/^>=?\s*\S+$/.test(constraint) && !constraint.includes("<") && !constraint.includes(",")) {
    return {
      manifest: "pyproject.toml",
      filePath,
      packageName: name,
      rawConstraint: constraint,
      severity: "medium",
      reason: "PEP 508: floor-only — declare an upper bound for supply-chain hygiene",
    };
  }
  return null;
}

function analyzeCargoToml(filePath: string, raw: string): DepFinding[] {
  const out: DepFinding[] = [];
  const lines = raw.split("\n");
  let inDeps = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("[")) {
      inDeps = trimmed === "[dependencies]" || trimmed === "[dev-dependencies]";
      continue;
    }
    if (!inDeps || !trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const name = trimmed.slice(0, eq).trim();
    const valueRaw = trimmed.slice(eq + 1).trim();
    if (valueRaw.startsWith("{")) continue;
    const constraint = valueRaw.replace(/^"|"$|,$/g, "").trim();
    if (constraint === "*" || constraint === "") {
      out.push({
        manifest: "Cargo.toml",
        filePath,
        packageName: name,
        rawConstraint: constraint,
        severity: "high",
        reason: "Cargo: wildcard pin — accepts any future release without review",
      });
    } else if (/^>=?\s*\d/.test(constraint) && !/<|,/.test(constraint)) {
      out.push({
        manifest: "Cargo.toml",
        filePath,
        packageName: name,
        rawConstraint: constraint,
        severity: "medium",
        reason: "Cargo: floor-only range; declare an upper bound to fix the supply-chain surface",
      });
    }
  }
  return out;
}

function analyzeGoMod(filePath: string, raw: string): DepFinding[] {
  const out: DepFinding[] = [];
  const requireBlock = /require\s*\(([\s\S]*?)\)/g;
  let match: RegExpExecArray | null;
  while ((match = requireBlock.exec(raw)) !== null) {
    const block = match[1] ?? "";
    for (const line of block.split("\n")) {
      const trimmed = line.trim().replace(/\s*\/\/.*$/, "");
      if (!trimmed) continue;
      const tokens = trimmed.split(/\s+/);
      if (tokens.length < 2) continue;
      const name = tokens[0]!;
      const version = tokens[1]!;
      if (/^v0\.0\.0-\d{14}-[a-f0-9]{12}$/.test(version)) {
        out.push({
          manifest: "go.mod",
          filePath,
          packageName: name,
          rawConstraint: version,
          severity: "medium",
          reason:
            "go.mod: pinned to a pseudo-version (commit hash); tag a release for an immutable pin",
        });
      } else if (version === "latest" || version === "v0.0.0") {
        out.push({
          manifest: "go.mod",
          filePath,
          packageName: name,
          rawConstraint: version,
          severity: "high",
          reason: "go.mod: floating latest / v0.0.0 — supply chain unstable",
        });
      }
    }
  }
  return out;
}

function formatFindings(findings: ReadonlyArray<DepFinding>, target: string): string {
  const lines: string[] = [
    `dep-hygiene: ${findings.length} risky specifier${findings.length === 1 ? "" : "s"} under ${target}`,
    "",
  ];
  const bySev: Record<DepFinding["severity"], DepFinding[]> = { high: [], medium: [], low: [] };
  for (const f of findings) bySev[f.severity].push(f);
  const order: ReadonlyArray<DepFinding["severity"]> = ["high", "medium", "low"];
  for (const sev of order) {
    if (bySev[sev].length === 0) continue;
    lines.push(`  [${sev.toUpperCase()}]`);
    for (const f of bySev[sev]) {
      lines.push(
        `    ${path.relative(target, f.filePath)} :: ${f.packageName}@${f.rawConstraint || "(empty)"} — ${f.reason}`,
      );
    }
    lines.push("");
  }
  return lines.join("\n").trimEnd();
}
