/**
 * Phase 0 — Detect attack surface per module via fast filesystem scanning.
 *
 * Grep-based detection of HTTP routes, websocket handlers, CLI commands,
 * RPC listeners, webhooks, and event listeners. Also detects web frameworks
 * from manifest files (reusing patterns from cross-service discovery).
 *
 * Pure regex over source files — zero LLM cost.
 */

import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import type { DiscoveredModule } from "../discovery/types.js";
import type { AttackSurfaceAnnotation, EntryPointType } from "./types.js";

const SKIP_DIRS = new Set([
  "node_modules",
  "vendor",
  ".git",
  "dist",
  "build",
  "target",
  ".next",
  ".kuzushi",
  "coverage",
  "__pycache__",
  ".venv",
  "venv",
  "__tests__",
  "test",
  "tests",
  "spec",
  "fixtures",
]);

const MAX_WALK_DEPTH = 4;
const MAX_FILES = 500;
const MAX_FILE_SIZE = 256 * 1024; // 256KB — skip large generated files

// ── Entry Point Detection Patterns ─────────────────────────────────────

interface EntryPointPattern {
  type: EntryPointType;
  pattern: RegExp;
}

const ENTRY_POINT_PATTERNS: EntryPointPattern[] = [
  // HTTP routes
  { type: "http-route", pattern: /\bapp\.(get|post|put|patch|delete|use|all)\s*\(/i },
  { type: "http-route", pattern: /\brouter\.(get|post|put|patch|delete|use|all)\s*\(/i },
  { type: "http-route", pattern: /@(Get|Post|Put|Patch|Delete|All|Options)\s*\(/i },
  { type: "http-route", pattern: /\bhttp\.Handle(Func)?\s*\(/i },
  { type: "http-route", pattern: /@app\.(get|post|put|route)\s*\(/i },
  { type: "http-route", pattern: /@(api_view|action)\s*\(/i },
  { type: "http-route", pattern: /\b#\[(get|post|put|delete)\s*\(/i },
  { type: "http-route", pattern: /@(RequestMapping|GetMapping|PostMapping)\s*\(/i },

  // WebSocket handlers
  { type: "websocket", pattern: /\bws\.(on|addEventListener)\s*\(/i },
  { type: "websocket", pattern: /@WebSocket(Gateway|Server)\b/i },
  { type: "websocket", pattern: /\bsocket\.(on|emit)\s*\(/i },
  { type: "websocket", pattern: /WebSocketServer|createWebSocketStream/i },

  // CLI commands
  { type: "cli-command", pattern: /\bnew\s+Command\s*\(/i },
  { type: "cli-command", pattern: /\.command\s*\(\s*['"`]/i },
  { type: "cli-command", pattern: /\bcobra\.(Command|Root)/i },
  { type: "cli-command", pattern: /clap::(App|Command|Arg)/i },
  { type: "cli-command", pattern: /@Cli(Command|Module)\s*\(/i },

  // Webhook handlers
  { type: "webhook", pattern: /webhook/i },
  { type: "webhook", pattern: /\/hooks?\//i },

  // RPC listeners
  { type: "rpc-listener", pattern: /\bgrpc\b/i },
  { type: "rpc-listener", pattern: /@GrpcMethod\s*\(/i },
  { type: "rpc-listener", pattern: /tonic::transport::Server/i },
  { type: "rpc-listener", pattern: /\.RegisterService\s*\(/i },

  // Event listeners (message queues, pub/sub)
  { type: "event-listener", pattern: /\.(on|subscribe|consume)\s*\(\s*['"`]\w/i },
  { type: "event-listener", pattern: /amqplib|kafkajs|bullmq|@nestjs\/microservices/i },
];

// ── Framework Detection (from manifest files) ──────────────────────────

interface FrameworkDetection {
  framework: string;
  language: string;
}

const MANIFEST_FRAMEWORK_CHECKS: Array<{
  file: string;
  patterns: Array<{ pattern: string; framework: string; language: string }>;
}> = [
  {
    file: "package.json",
    patterns: [
      { pattern: '"express"', framework: "express", language: "javascript" },
      { pattern: '"@nestjs/core"', framework: "nestjs", language: "javascript" },
      { pattern: '"fastify"', framework: "fastify", language: "javascript" },
      { pattern: '"next"', framework: "next", language: "javascript" },
      { pattern: '"@hapi/hapi"', framework: "hapi", language: "javascript" },
      { pattern: '"koa"', framework: "koa", language: "javascript" },
    ],
  },
  {
    file: "go.mod",
    patterns: [
      { pattern: "github.com/gin-gonic/gin", framework: "gin", language: "go" },
      { pattern: "github.com/labstack/echo", framework: "echo", language: "go" },
      { pattern: "net/http", framework: "net-http", language: "go" },
    ],
  },
  {
    file: "requirements.txt",
    patterns: [
      { pattern: "fastapi", framework: "fastapi", language: "python" },
      { pattern: "django", framework: "django", language: "python" },
      { pattern: "flask", framework: "flask", language: "python" },
    ],
  },
  {
    file: "pom.xml",
    patterns: [{ pattern: "spring", framework: "spring", language: "java" }],
  },
];

// ── Public API ──────────────────────────────────────────────────────────

/**
 * Detect the attack surface of each module: entry point types, count,
 * frameworks, and whether it's external-facing.
 */
export async function detectAttackSurfaces(
  monorepoRoot: string,
  modules: DiscoveredModule[],
): Promise<Map<string, AttackSurfaceAnnotation>> {
  const results = new Map<string, AttackSurfaceAnnotation>();

  for (const m of modules) {
    const effectivePaths = m.includePaths ?? [m.path];
    const annotations = await Promise.all(
      effectivePaths.map((p) => detectModuleAttackSurface(path.resolve(monorepoRoot, p))),
    );
    results.set(m.path, mergeAttackSurfaceAnnotations(annotations));
  }

  return results;
}

async function detectModuleAttackSurface(moduleDir: string): Promise<AttackSurfaceAnnotation> {
  const entryPointCounts = new Map<EntryPointType, number>();
  const detectedFrameworks: FrameworkDetection[] = [];

  // Check manifest files for frameworks
  for (const check of MANIFEST_FRAMEWORK_CHECKS) {
    const filePath = path.join(moduleDir, check.file);
    try {
      const content = await readFile(filePath, "utf-8");
      const lower = content.toLowerCase();
      for (const p of check.patterns) {
        if (lower.includes(p.pattern.toLowerCase())) {
          detectedFrameworks.push({ framework: p.framework, language: p.language });
        }
      }
    } catch {
      // File doesn't exist, skip
    }
  }

  // Walk source files and grep for entry point patterns
  const sourceFiles = await collectSourceFiles(moduleDir);

  for (const filePath of sourceFiles) {
    try {
      const fstat = await stat(filePath);
      if (fstat.size > MAX_FILE_SIZE) continue;

      const content = await readFile(filePath, "utf-8");
      for (const ep of ENTRY_POINT_PATTERNS) {
        const matches = content.match(new RegExp(ep.pattern.source, "gim"));
        if (matches) {
          entryPointCounts.set(ep.type, (entryPointCounts.get(ep.type) ?? 0) + matches.length);
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  const entryPointTypes = [...entryPointCounts.keys()];
  const entryPointCount = [...entryPointCounts.values()].reduce((a, b) => a + b, 0);
  const isExternalFacing = entryPointTypes.some(
    (t) => t === "http-route" || t === "websocket" || t === "webhook" || t === "rpc-listener",
  );

  return {
    isExternalFacing,
    entryPointTypes,
    entryPointCount,
    detectedFrameworks: detectedFrameworks.map((f) => f.framework),
  };
}

function mergeAttackSurfaceAnnotations(
  annotations: AttackSurfaceAnnotation[],
): AttackSurfaceAnnotation {
  if (annotations.length === 0) {
    return {
      isExternalFacing: false,
      entryPointTypes: [],
      entryPointCount: 0,
      detectedFrameworks: [],
    };
  }
  if (annotations.length === 1) return annotations[0];

  const entryPointTypes = new Set<EntryPointType>();
  const detectedFrameworks = new Set<string>();
  let entryPointCount = 0;
  let isExternalFacing = false;

  for (const a of annotations) {
    if (a.isExternalFacing) isExternalFacing = true;
    for (const t of a.entryPointTypes) entryPointTypes.add(t);
    for (const f of a.detectedFrameworks) detectedFrameworks.add(f);
    entryPointCount += a.entryPointCount;
  }

  return {
    isExternalFacing,
    entryPointTypes: [...entryPointTypes],
    entryPointCount,
    detectedFrameworks: [...detectedFrameworks],
  };
}

// ── File Walking ───────────────────────────────────────────────────────

const SOURCE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".go",
  ".rs",
  ".java",
  ".kt",
  ".cs",
  ".rb",
  ".php",
]);

async function collectSourceFiles(
  dir: string,
  depth = 0,
  collected: string[] = [],
): Promise<string[]> {
  if (depth > MAX_WALK_DEPTH || collected.length >= MAX_FILES) return collected;

  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return collected;
  }

  for (const name of names) {
    if (collected.length >= MAX_FILES) break;

    const fullPath = path.join(dir, name);
    let fstat: Awaited<ReturnType<typeof stat>>;
    try {
      fstat = await stat(fullPath);
    } catch {
      continue;
    }

    if (fstat.isDirectory()) {
      if (!SKIP_DIRS.has(name) && !name.startsWith(".")) {
        await collectSourceFiles(fullPath, depth + 1, collected);
      }
    } else if (fstat.isFile()) {
      const ext = path.extname(name).toLowerCase();
      if (SOURCE_EXTENSIONS.has(ext)) {
        collected.push(fullPath);
      }
    }
  }

  return collected;
}

/**
 * Format a summary of attack surfaces for logging.
 */
export function formatAttackSurfaceSummary(surfaces: Map<string, AttackSurfaceAnnotation>): string {
  const lines: string[] = [];
  const sorted = [...surfaces.entries()].sort(([, a], [, b]) => {
    if (a.isExternalFacing !== b.isExternalFacing) return a.isExternalFacing ? -1 : 1;
    return b.entryPointCount - a.entryPointCount;
  });

  for (const [name, surface] of sorted.slice(0, 15)) {
    const tag = surface.isExternalFacing ? "EXTERNAL" : "internal";
    const frameworks =
      surface.detectedFrameworks.length > 0 ? ` (${surface.detectedFrameworks.join(", ")})` : "";
    const types = surface.entryPointTypes.join(", ") || "none";
    lines.push(
      `  [${tag}] ${name}: ${surface.entryPointCount} entry points (${types})${frameworks}`,
    );
  }
  return lines.join("\n");
}
