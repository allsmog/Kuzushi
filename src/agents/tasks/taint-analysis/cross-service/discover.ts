import { existsSync } from "node:fs";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { isRecord } from "../../../../utils.js";
import type { AgentTask } from "../../../types.js";
import { resolveTaintAnalysisConfig } from "../types.js";
import type { ScanOpts } from "../../../../types.js";
import {
  resolveCrossServiceConfig,
  type CrossServiceDiscoverOutput,
  type ServiceDescriptor,
  type ServiceManifest,
  type ServiceManifestEntry,
} from "./types.js";

const MAX_WALK_DEPTH = 3;

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
]);

// ── Framework Detection Patterns ────────────────────────────────────────

interface FrameworkPattern {
  file: string;
  detect: (content: string) => { language: string; framework: string | null }[];
}

const FRAMEWORK_PATTERNS: FrameworkPattern[] = [
  {
    file: "package.json",
    detect: (content) => {
      const lower = content.toLowerCase();
      const results: { language: string; framework: string | null }[] = [];
      if (lower.includes("\"express\"")) results.push({ language: "javascript", framework: "express" });
      if (lower.includes("\"@nestjs/core\"")) results.push({ language: "javascript", framework: "nestjs" });
      if (lower.includes("\"fastify\"")) results.push({ language: "javascript", framework: "fastify" });
      if (lower.includes("\"next\"")) results.push({ language: "javascript", framework: "next" });
      if (results.length === 0 && (lower.includes("\"dependencies\"") || lower.includes("\"devdependencies\""))) {
        results.push({ language: "javascript", framework: null });
      }
      return results;
    },
  },
  {
    file: "go.mod",
    detect: (content) => {
      const lower = content.toLowerCase();
      const results: { language: string; framework: string | null }[] = [];
      if (lower.includes("github.com/gin-gonic/gin")) results.push({ language: "go", framework: "gin" });
      else if (lower.includes("github.com/labstack/echo")) results.push({ language: "go", framework: "echo" });
      else results.push({ language: "go", framework: null });
      return results;
    },
  },
  {
    file: "requirements.txt",
    detect: (content) => {
      const lower = content.toLowerCase();
      const results: { language: string; framework: string | null }[] = [];
      if (lower.includes("fastapi")) results.push({ language: "python", framework: "fastapi" });
      else if (lower.includes("django")) results.push({ language: "python", framework: "django" });
      else if (lower.includes("flask")) results.push({ language: "python", framework: "flask" });
      else results.push({ language: "python", framework: null });
      return results;
    },
  },
  {
    file: "pyproject.toml",
    detect: (content) => {
      const lower = content.toLowerCase();
      const results: { language: string; framework: string | null }[] = [];
      if (lower.includes("fastapi")) results.push({ language: "python", framework: "fastapi" });
      else if (lower.includes("django")) results.push({ language: "python", framework: "django" });
      else if (lower.includes("flask")) results.push({ language: "python", framework: "flask" });
      else results.push({ language: "python", framework: null });
      return results;
    },
  },
  {
    file: "pom.xml",
    detect: (content) => {
      const lower = content.toLowerCase();
      if (lower.includes("spring")) return [{ language: "java", framework: "spring" }];
      return [{ language: "java", framework: null }];
    },
  },
  {
    file: "build.gradle",
    detect: (content) => {
      const lower = content.toLowerCase();
      if (lower.includes("spring")) return [{ language: "java", framework: "spring" }];
      return [{ language: "java", framework: null }];
    },
  },
];

// ── Task Definition ─────────────────────────────────────────────────────

export const taintAnalysisDiscoverTask: AgentTask<ScanOpts, CrossServiceDiscoverOutput> = {
  id: "taint-analysis-discover",
  displayName: "Cross-Service Discovery",
  outputKind: "custom",
  dependsOn: [],
  condition: (_upstreamOutputs, config) => {
    const cfg = resolveTaintAnalysisConfig(config);
    return resolveCrossServiceConfig(cfg).enabled;
  },
  async run(_input, context): Promise<CrossServiceDiscoverOutput> {
    const cfg = resolveTaintAnalysisConfig(context.config);
    const crossCfg = resolveCrossServiceConfig(cfg);
    const projectRoot = context.projectRoot ?? context.repoRoot;

    // Check for manifest override
    const manifestPath = path.join(projectRoot, ".kuzushi", "services.json");
    if (existsSync(manifestPath)) {
      const manifest = await loadManifest(manifestPath);
      const services = manifest.services
        .slice(0, crossCfg.maxServices)
        .map((entry) => manifestEntryToDescriptor(entry))
        .filter((svc) => isWithinRepoRoot(projectRoot, svc.rootPath));
      return {
        services,
        usedManifest: true,
        autoDetectedPaths: [],
      };
    }

    // Auto-detect services
    const detectedPaths: string[] = [];
    const services = await autoDetectServices(
      projectRoot,
      crossCfg.maxServices,
      detectedPaths,
    );

    return {
      services,
      usedManifest: false,
      autoDetectedPaths: detectedPaths,
    };
  },
};

// ── Manifest Loading ────────────────────────────────────────────────────

async function loadManifest(manifestPath: string): Promise<ServiceManifest> {
  const raw = await readFile(manifestPath, "utf-8");
  const parsed = JSON.parse(raw);
  if (!isRecord(parsed) || !Array.isArray(parsed["services"])) {
    throw new Error(`Invalid services manifest at ${manifestPath}: must contain a "services" array`);
  }

  const version = typeof parsed["version"] === "string" ? parsed["version"] : "1.0.0";
  const services: ServiceManifestEntry[] = [];
  for (const entry of parsed["services"]) {
    if (!isRecord(entry)) continue;
    const id = typeof entry["id"] === "string" ? entry["id"].trim() : "";
    const rootPath = typeof entry["rootPath"] === "string" ? entry["rootPath"].trim() : "";
    const language = typeof entry["language"] === "string" ? entry["language"].trim().toLowerCase() : "";
    if (!id || !rootPath || !language) continue;
    services.push({
      id,
      displayName: typeof entry["displayName"] === "string" ? entry["displayName"].trim() : id,
      rootPath,
      language,
      framework: typeof entry["framework"] === "string" ? entry["framework"].trim() || undefined : undefined,
    });
  }

  return { version, services };
}

function manifestEntryToDescriptor(entry: ServiceManifestEntry): ServiceDescriptor {
  return {
    id: entry.id,
    displayName: entry.displayName ?? entry.id,
    rootPath: entry.rootPath,
    language: entry.language,
    framework: entry.framework ?? null,
    discoveryMethod: "manifest",
    manifestFiles: [],
  };
}

// ── Auto-Detection ──────────────────────────────────────────────────────

async function autoDetectServices(
  repoRoot: string,
  maxServices: number,
  detectedPaths: string[],
): Promise<ServiceDescriptor[]> {
  const services: ServiceDescriptor[] = [];
  const stack: Array<{ relDir: string; depth: number }> = [{ relDir: "", depth: 0 }];

  while (stack.length > 0 && services.length < maxServices) {
    const item = stack.pop();
    if (!item) break;

    const absDir = path.join(repoRoot, item.relDir);
    let entries: string[];
    try {
      entries = await readdir(absDir);
    } catch {
      continue;
    }

    const detected = await detectServiceInDir(absDir, item.relDir, entries);
    if (detected) {
      services.push(detected);
      detectedPaths.push(item.relDir || ".");
      // Don't recurse into detected service directories
      continue;
    }

    // Recurse into subdirectories
    if (item.depth < MAX_WALK_DEPTH) {
      for (const entry of entries.sort()) {
        if (SKIP_DIRS.has(entry) || entry.startsWith(".")) continue;
        const childRel = item.relDir ? `${item.relDir}/${entry}` : entry;
        const childAbs = path.join(absDir, entry);
        try {
          const st = await stat(childAbs);
          if (st.isDirectory()) {
            stack.push({ relDir: childRel, depth: item.depth + 1 });
          }
        } catch {
          // skip unreadable
        }
      }
    }
  }

  return services;
}

async function detectServiceInDir(
  absDir: string,
  relDir: string,
  entries: string[],
): Promise<ServiceDescriptor | null> {
  const entrySet = new Set(entries);

  for (const pattern of FRAMEWORK_PATTERNS) {
    if (!entrySet.has(pattern.file)) continue;
    const filePath = path.join(absDir, pattern.file);
    const content = await readText(filePath);
    if (!content) continue;

    const detections = pattern.detect(content);
    if (detections.length === 0) continue;

    const primary = detections[0];
    const id = relDir
      ? relDir.replace(/\//g, "-").replace(/^-+|-+$/g, "")
      : path.basename(absDir);
    const displayName = humanize(id);

    const manifestFiles = [pattern.file];

    return {
      id,
      displayName,
      rootPath: relDir || ".",
      language: primary.language,
      framework: primary.framework,
      discoveryMethod: "auto",
      manifestFiles,
    };
  }

  // Check for Java (build.gradle.kts)
  if (entrySet.has("build.gradle.kts")) {
    const content = await readText(path.join(absDir, "build.gradle.kts"));
    if (content) {
      const lower = content.toLowerCase();
      const framework = lower.includes("spring") ? "spring" : null;
      const id = relDir
        ? relDir.replace(/\//g, "-").replace(/^-+|-+$/g, "")
        : path.basename(absDir);
      return {
        id,
        displayName: humanize(id),
        rootPath: relDir || ".",
        language: "java",
        framework,
        discoveryMethod: "auto",
        manifestFiles: ["build.gradle.kts"],
      };
    }
  }

  // Check for C# .csproj files
  for (const entry of entries) {
    if (entry.endsWith(".csproj")) {
      const content = await readText(path.join(absDir, entry));
      if (content) {
        const lower = content.toLowerCase();
        const framework = lower.includes("aspnetcore") || lower.includes("webapplication")
          ? "aspnet"
          : null;
        const id = relDir
          ? relDir.replace(/\//g, "-").replace(/^-+|-+$/g, "")
          : path.basename(absDir);
        return {
          id,
          displayName: humanize(id),
          rootPath: relDir || ".",
          language: "csharp",
          framework,
          discoveryMethod: "auto",
          manifestFiles: [entry],
        };
      }
    }
  }

  return null;
}

// ── Helpers ─────────────────────────────────────────────────────────────

async function readText(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, "utf-8");
  } catch {
    return null;
  }
}

function isWithinRepoRoot(repoRoot: string, rootPath: string): boolean {
  const resolved = path.resolve(repoRoot, rootPath);
  const relative = path.relative(repoRoot, resolved);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function humanize(id: string): string {
  return id
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim() || id;
}

export const __discoverInternals = {
  loadManifest,
  autoDetectServices,
  detectServiceInDir,
  manifestEntryToDescriptor,
};
