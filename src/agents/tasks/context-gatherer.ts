import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORED_DIRS, walkRepo as walkRepoEntries } from "../../repo-walk.js";
import type { FileIndex, RepoContext, ScanOpts, SecurityPatternMatch } from "../../types.js";
import { isRecord } from "../../utils.js";
import type { DagNodeImpl } from "../types.js";

const MAX_WALK_DEPTH = 5;
const MAX_WALK_ENTRIES = 4000;

const MAX_FILE_INDEX_ENTRIES = 500;

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
  ".rb",
  ".php",
  ".cs",
  ".c",
  ".cpp",
  ".h",
  ".hpp",
  ".swift",
  ".scala",
  ".sh",
  ".bash",
  ".yml",
  ".yaml",
  ".json",
  ".toml",
  ".ini",
  ".conf",
  ".cfg",
  ".env",
  ".xml",
  ".html",
  ".vue",
  ".svelte",
  ".dockerfile",
  ".tf",
]);

const MAX_GREP_FILE_SIZE = 100_000;
const MAX_MATCHES_PER_DOMAIN = 50;

const SECURITY_GREP_PATTERNS: Record<
  string,
  { fileFilter?: (p: string) => boolean; patterns: RegExp[] }
> = {
  "crypto-import": {
    patterns: [
      /require\(['"]crypto['"]\)/,
      /from\s+['"]crypto['"]/,
      /hashlib/,
      /javax\.crypto/,
      /bcrypt/,
      /argon2/,
    ],
  },
  "eval-exec": {
    patterns: [
      /\beval\s*\(/,
      /\bexec\s*\(/,
      /\bspawn\s*\(/,
      /\bFunction\s*\(/,
      /child_process/,
      /subprocess/,
      /os\.system/,
    ],
  },
  "auth-session": {
    patterns: [/\bpassport\b/, /\bjwt\b/i, /\bsession\b/, /\bmiddleware\b/],
    fileFilter: (p) => /\.(ts|js|py|go|java|rb|php)$/i.test(p),
  },
  "secret-pattern": {
    patterns: [
      /AKIA[A-Z0-9]{16}/,
      /BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY/,
      /password\s*[:=]/i,
      /api[_-]?key\s*[:=]/i,
    ],
    fileFilter: (p) => /\.(env|json|yml|yaml|toml|ini|conf|cfg|ts|js|py)$/i.test(p),
  },
  "config-security": {
    fileFilter: (p) => /\.(yml|yaml|json|toml|ini|conf|cfg|env)$/i.test(p) || /config/i.test(p),
    patterns: [/\bcors\b/i, /\bhelmet\b/, /\bcsrf\b/i, /debug\s*[:=]\s*true/i],
  },
  "protocol-parser": {
    fileFilter: (p) => /\.(c|cpp|cc|cxx|h|hpp|hxx|rs)$/i.test(p),
    patterns: [
      /\btcp\b/i,
      /\budp\b/i,
      /\bpacket\b/i,
      /\bsegment\b/i,
      /\bsack\b/i,
      /\brpc\b/i,
      /\bnfs\b/i,
      /\bgss\b/i,
      /\bxdr\b/i,
      /\bcodec\b/i,
      /\bdecode\b/i,
      /\bh264\b/i,
      /\bslice\b/i,
      /\bframe\b/i,
      /\bparser\b/i,
    ],
  },
  "integer-boundary": {
    fileFilter: (p) => /\.(c|cpp|cc|cxx|h|hpp|hxx)$/i.test(p),
    patterns: [
      /\bINT_MAX\b/,
      /\bINT_MIN\b/,
      /\bUINT_MAX\b/,
      /\bSIZE_MAX\b/,
      /\bUINT16_MAX\b/,
      /\bUINT32_MAX\b/,
      /\b0xFFFF\b/i,
      /\b0xFFFFFFFF\b/i,
      /\(int\)\s*\w+/,
      /\(unsigned\)\s*\w+/,
    ],
  },
  "unsafe-memory": {
    fileFilter: (p) => /\.(c|cpp|cc|cxx|h|hpp|hxx|rs)$/i.test(p),
    patterns: [
      /\bunsafe\s*\{/,
      /\bunsafe\s+fn\b/,
      /\bmemcpy\s*\(/,
      /\bmemmove\s*\(/,
      /\bstrcpy\s*\(/,
      /\bsprintf\s*\(/,
      /\bmalloc\s*\(/,
      /\bcalloc\s*\(/,
      /\brealloc\s*\(/,
      /\bfree\s*\(/,
      /\bptr::write\b/,
      /\bstd::mem::transmute\b/,
    ],
  },
  hardening: {
    fileFilter: (p) => /\.(c|cpp|cc|cxx|h|hpp|hxx|rs|toml|mk|cmake)$/i.test(p),
    patterns: [
      /\b__stack_chk_fail\b/,
      /\bstack[-_ ]canary\b/i,
      /\bFORTIFY_SOURCE\b/,
      /\bpanic!\b/,
      /\bdebug_assert!\b/,
      /\bassert\s*\(/,
      /\bfrom_raw_parts\b/,
      /\bget_unchecked\b/,
      /\bset_len\b/,
    ],
  },
};

export interface ContextGathererOutput {
  repoContext: RepoContext;
  fileIndex: FileIndex;
}

// ── Live-build phase observer ─────────────────────────────────────────────
//
// Optional observer hook that `gatherContextForRoot` can drive to stream
// per-phase progress into an Ink view (see `ContextBuildView`). All callers
// remain source-compatible — omitting the observer reproduces the prior
// behaviour exactly.
export type BuildPhaseId = "manifests" | "walk" | "path-signals" | "grep" | "assemble";

export type ManifestProbe = "package.json" | "go.mod" | "pyproject" | "Cargo.toml" | "native-build";

export type ContextBuildEvent =
  | { type: "phase-start"; phase: BuildPhaseId; atMs: number }
  | { type: "phase-done"; phase: BuildPhaseId; atMs: number; durationMs: number }
  | { type: "manifest-result"; which: ManifestProbe; found: boolean }
  | { type: "walk-result"; entries: number; dirs: number; sourceFiles: number; cap: number }
  | { type: "path-signals-result"; signals: string[] }
  | {
      type: "grep-start";
      filesTotal: number;
      workers: number;
      domainCap: number;
      domains: string[];
    }
  | { type: "grep-file-progress"; filesDone: number; filesTotal: number }
  | {
      type: "grep-domain-state";
      domain: string;
      matches: number;
      status: "active" | "capped" | "skipped-no-ext";
    }
  | {
      type: "assemble-result";
      repoContext: RepoContext;
      sourceFileCount: number;
      patternMatchCount: number;
    }
  | { type: "tail"; tsMs: number; message: string; kind?: "info" | "warn" };

export type ContextBuildObserver = (event: ContextBuildEvent) => void;

interface MutableRepoContext {
  languages: Set<string>;
  frameworks: Set<string>;
  authPatterns: Set<string>;
  sanitizationLibs: Set<string>;
  ormOrDb: Set<string>;
  entryPoints: Set<string>;
}

interface WalkEntry {
  relPath: string;
}

interface PathSignals {
  files: WalkEntry[];
  fileSet: Set<string>;
  dirs: Set<string>;
}

/**
 * Deterministic, non-AI pre-scan repository context gathering task.
 */
export const contextGathererTask: DagNodeImpl<ScanOpts, ContextGathererOutput> = {
  id: "context-gatherer",
  displayName: "Context Gatherer",
  outputKind: "custom",
  dependsOn: [],
  async run(_input, context): Promise<ContextGathererOutput> {
    context.signal?.throwIfAborted();
    return gatherContextForRoot(context.workRoot ?? context.repoRoot, context.signal);
  },
};

export async function gatherContextForRoot(
  workRoot: string,
  signal?: AbortSignal,
  observer?: ContextBuildObserver,
): Promise<ContextGathererOutput> {
  const aggregate = createMutableRepoContext();
  const emit = observer ?? (() => undefined);
  const phaseTimer = makePhaseTimer(emit);

  // ── Phase 1: manifest probes ─────────────────────────────────────────
  phaseTimer.start("manifests");
  const manifestProbes: ReadonlyArray<{
    which: ManifestProbe;
    files: string[];
    run: () => Promise<void>;
  }> = [
    {
      which: "package.json",
      files: ["package.json"],
      run: () => gatherFromPackageJson(workRoot, aggregate),
    },
    { which: "go.mod", files: ["go.mod"], run: () => gatherFromGoMod(workRoot, aggregate) },
    {
      which: "pyproject",
      files: ["pyproject.toml", "requirements.txt"],
      run: () => gatherFromPython(workRoot, aggregate),
    },
    {
      which: "Cargo.toml",
      files: ["Cargo.toml"],
      run: () => gatherFromCargoToml(workRoot, aggregate),
    },
    {
      which: "native-build",
      files: ["CMakeLists.txt", "Makefile", "configure.ac", "meson.build"],
      run: () => gatherFromNativeBuildSystem(workRoot, aggregate),
    },
  ];
  await Promise.all(
    manifestProbes.map(async (probe) => {
      const found = (
        await Promise.all(probe.files.map((f) => pathExists(path.join(workRoot, f))))
      ).some(Boolean);
      await probe.run();
      emit({ type: "manifest-result", which: probe.which, found });
    }),
  );
  phaseTimer.done("manifests");
  signal?.throwIfAborted();

  // ── Phase 2: walk repo ───────────────────────────────────────────────
  phaseTimer.start("walk");
  const pathSignals = await walkRepo(workRoot);
  const sourceFiles = pathSignals.files.filter((file) =>
    SOURCE_EXTENSIONS.has(path.extname(file.relPath).toLowerCase()),
  );
  emit({
    type: "walk-result",
    entries: pathSignals.files.length + pathSignals.dirs.size,
    dirs: pathSignals.dirs.size,
    sourceFiles: sourceFiles.length,
    cap: MAX_WALK_ENTRIES,
  });
  phaseTimer.done("walk");
  signal?.throwIfAborted();

  // ── Phase 3: path signals ────────────────────────────────────────────
  phaseTimer.start("path-signals");
  gatherFromPathSignals(pathSignals, aggregate);
  emit({ type: "path-signals-result", signals: describePathSignals(pathSignals) });
  phaseTimer.done("path-signals");

  // ── Phase 4: grep sweep ──────────────────────────────────────────────
  phaseTimer.start("grep");
  const tree = sourceFiles.slice(0, MAX_FILE_INDEX_ENTRIES).map((file) => ({ path: file.relPath }));
  const patternMatches = await grepSecurityPatterns(workRoot, sourceFiles, signal, emit);
  phaseTimer.done("grep");

  // ── Phase 5: assemble ────────────────────────────────────────────────
  phaseTimer.start("assemble");
  const repoContext: RepoContext = {
    languages: sortValues(aggregate.languages),
    frameworks: sortValues(aggregate.frameworks),
    authPatterns: sortValues(aggregate.authPatterns),
    sanitizationLibs: sortValues(aggregate.sanitizationLibs),
    ormOrDb: sortValues(aggregate.ormOrDb),
    entryPoints: sortValues(aggregate.entryPoints),
  };
  const patternMatchCount = Object.values(patternMatches).reduce((sum, arr) => sum + arr.length, 0);
  emit({
    type: "assemble-result",
    repoContext,
    sourceFileCount: sourceFiles.length,
    patternMatchCount,
  });
  phaseTimer.done("assemble");

  return {
    repoContext,
    fileIndex: {
      tree,
      totalFiles: sourceFiles.length,
      truncated: sourceFiles.length > MAX_FILE_INDEX_ENTRIES,
      patternMatches,
    },
  };
}

function makePhaseTimer(emit: ContextBuildObserver): {
  start: (phase: BuildPhaseId) => void;
  done: (phase: BuildPhaseId) => void;
} {
  const startedAt = new Map<BuildPhaseId, number>();
  return {
    start(phase) {
      const atMs = Date.now();
      startedAt.set(phase, atMs);
      emit({ type: "phase-start", phase, atMs });
    },
    done(phase) {
      const atMs = Date.now();
      const started = startedAt.get(phase) ?? atMs;
      emit({ type: "phase-done", phase, atMs, durationMs: atMs - started });
    },
  };
}

function describePathSignals(signals: PathSignals): string[] {
  const hits: string[] = [];
  if ([...signals.dirs].some((d) => d.includes("/auth") || d.startsWith("auth")))
    hits.push("auth/");
  if ([...signals.dirs].some((d) => d.includes("/middleware") || d.startsWith("middleware")))
    hits.push("middleware/");
  if (signals.fileSet.has("Dockerfile")) hits.push("Dockerfile");
  if (signals.fileSet.has("docker-compose.yml") || signals.fileSet.has("docker-compose.yaml"))
    hits.push("docker-compose");
  if ([...signals.fileSet].some((f) => f.startsWith("src/pages/api/"))) hits.push("src/pages/api/");
  if ([...signals.fileSet].some((f) => f.startsWith("src/app/api/"))) hits.push("src/app/api/");
  return hits;
}

const GREP_CONCURRENCY = 16;

async function grepSecurityPatterns(
  repoRoot: string,
  files: WalkEntry[],
  signal?: AbortSignal,
  emit: ContextBuildObserver = () => undefined,
): Promise<Record<string, SecurityPatternMatch[]>> {
  const domains = Object.keys(SECURITY_GREP_PATTERNS);
  const result: Record<string, SecurityPatternMatch[]> = {};
  for (const domain of domains) result[domain] = [];

  // Which domains have at least one file that passes their `fileFilter`?
  // Domains that match nothing get an immediate `skipped-no-ext` so the
  // view can render that state from the start of the sweep — matching the
  // design's "skipped (no matching ext)" label.
  const domainEligible = new Map<string, boolean>();
  for (const domain of domains) {
    const spec = SECURITY_GREP_PATTERNS[domain];
    const eligible = spec.fileFilter
      ? files.some((f) => (spec.fileFilter as (p: string) => boolean)(f.relPath))
      : files.length > 0;
    domainEligible.set(domain, eligible);
    if (!eligible)
      emit({ type: "grep-domain-state", domain, matches: 0, status: "skipped-no-ext" });
  }

  const workers = Math.min(GREP_CONCURRENCY, Math.max(files.length, 1));
  emit({
    type: "grep-start",
    filesTotal: files.length,
    workers,
    domainCap: MAX_MATCHES_PER_DOMAIN,
    domains,
  });

  const domainCapEmitted = new Set<string>();
  let filesDone = 0;
  let lastProgressAtMs = 0;
  const PROGRESS_FILE_INTERVAL = 25;
  const PROGRESS_MS_INTERVAL = 200;

  // Process files with bounded concurrency instead of sequentially
  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < files.length) {
      if (signal?.aborted) return;
      const idx = cursor++;
      const file = files[idx];
      const absPath = path.join(repoRoot, file.relPath);

      let fileSize: number;
      try {
        const s = await stat(absPath);
        fileSize = s.size;
      } catch {
        advanceFileCounter();
        continue;
      }
      if (fileSize > MAX_GREP_FILE_SIZE) {
        advanceFileCounter();
        continue;
      }

      let content: string;
      try {
        content = await readFile(absPath, "utf-8");
      } catch {
        advanceFileCounter();
        continue;
      }

      const lines = content.split("\n");

      for (const [domain, spec] of Object.entries(SECURITY_GREP_PATTERNS)) {
        if (result[domain].length >= MAX_MATCHES_PER_DOMAIN) continue;
        if (spec.fileFilter && !spec.fileFilter(file.relPath)) continue;

        for (let i = 0; i < lines.length; i++) {
          if (result[domain].length >= MAX_MATCHES_PER_DOMAIN) break;
          const line = lines[i];
          for (const pattern of spec.patterns) {
            if (pattern.test(line)) {
              result[domain].push({
                pattern: pattern.source,
                filePath: file.relPath,
                lineNumber: i + 1,
                lineContent: line.slice(0, 200),
              });
              break; // one match per line per domain
            }
          }
        }

        if (result[domain].length >= MAX_MATCHES_PER_DOMAIN && !domainCapEmitted.has(domain)) {
          domainCapEmitted.add(domain);
          emit({
            type: "grep-domain-state",
            domain,
            matches: result[domain].length,
            status: "capped",
          });
        }
      }

      advanceFileCounter();
    }
  };

  function advanceFileCounter(): void {
    filesDone += 1;
    const now = Date.now();
    const intervalReached = filesDone % PROGRESS_FILE_INTERVAL === 0;
    const dueByTime = now - lastProgressAtMs >= PROGRESS_MS_INTERVAL;
    const isLast = filesDone === files.length;
    if (intervalReached || dueByTime || isLast) {
      lastProgressAtMs = now;
      emit({ type: "grep-file-progress", filesDone, filesTotal: files.length });
    }
  }

  await Promise.all(Array.from({ length: workers }, () => worker()));

  // On completion, emit the final active counts for any eligible, non-capped
  // domain so the view can show the tally even if the cap was never hit.
  for (const domain of domains) {
    if (!domainEligible.get(domain)) continue;
    if (domainCapEmitted.has(domain)) continue;
    emit({
      type: "grep-domain-state",
      domain,
      matches: result[domain].length,
      status: "active",
    });
  }

  return result;
}

function createMutableRepoContext(): MutableRepoContext {
  return {
    languages: new Set<string>(),
    frameworks: new Set<string>(),
    authPatterns: new Set<string>(),
    sanitizationLibs: new Set<string>(),
    ormOrDb: new Set<string>(),
    entryPoints: new Set<string>(),
  };
}

async function gatherFromPackageJson(repoRoot: string, out: MutableRepoContext): Promise<void> {
  const packageJson = await readJson(path.join(repoRoot, "package.json"));
  if (!packageJson) {
    return;
  }

  const depNames = extractDependencyNames(packageJson);
  if (depNames.size === 0) {
    return;
  }

  out.languages.add(depNames.has("typescript") ? "TypeScript" : "JavaScript");

  maybeAdd(out.frameworks, depNames, ["next"], "Next.js");
  maybeAdd(out.frameworks, depNames, ["express"], "Express");
  maybeAdd(out.frameworks, depNames, ["react"], "React");
  maybeAdd(out.frameworks, depNames, ["@nestjs/core"], "NestJS");
  maybeAdd(
    out.frameworks,
    depNames,
    ["graphql", "@apollo/server", "apollo-server", "mercurius"],
    "GraphQL",
  );

  maybeAdd(out.authPatterns, depNames, ["jsonwebtoken", "jose", "passport-jwt"], "JWT");
  maybeAdd(out.authPatterns, depNames, ["express-session", "iron-session"], "session-based");
  maybeAdd(out.authPatterns, depNames, ["next-auth", "passport-oauth2", "oauth2-server"], "OAuth");

  maybeAdd(out.sanitizationLibs, depNames, ["helmet"], "helmet");
  maybeAdd(out.sanitizationLibs, depNames, ["dompurify"], "DOMPurify");
  maybeAdd(out.sanitizationLibs, depNames, ["sanitize-html", "xss"], "sanitize-html");

  maybeAdd(out.ormOrDb, depNames, ["prisma", "@prisma/client"], "Prisma");
  maybeAdd(out.ormOrDb, depNames, ["sequelize"], "Sequelize");
  maybeAdd(out.ormOrDb, depNames, ["typeorm"], "TypeORM");
  maybeAdd(out.ormOrDb, depNames, ["mongoose"], "Mongoose");
  maybeAdd(out.ormOrDb, depNames, ["knex"], "Knex");

  if (await pathExists(path.join(repoRoot, "src/pages/api"))) {
    out.entryPoints.add("src/pages/api/*");
  }
  if (await pathExists(path.join(repoRoot, "src/app/api"))) {
    out.entryPoints.add("src/app/api/*");
  }
  if (await pathExists(path.join(repoRoot, "src/server.ts"))) {
    out.entryPoints.add("src/server.ts");
  }
  if (await pathExists(path.join(repoRoot, "src/index.ts"))) {
    out.entryPoints.add("src/index.ts");
  }
}

async function gatherFromGoMod(repoRoot: string, out: MutableRepoContext): Promise<void> {
  const content = await readText(path.join(repoRoot, "go.mod"));
  if (!content) {
    return;
  }

  const lower = content.toLowerCase();
  out.languages.add("Go");

  if (lower.includes("github.com/gin-gonic/gin")) {
    out.frameworks.add("Gin");
  }
  if (lower.includes("github.com/labstack/echo")) {
    out.frameworks.add("Echo");
  }
  if (lower.includes("jwt") || lower.includes("jwx")) {
    out.authPatterns.add("JWT");
  }
  if (lower.includes("oauth")) {
    out.authPatterns.add("OAuth");
  }
  if (lower.includes("gorm.io/gorm")) {
    out.ormOrDb.add("GORM");
  }

  if (await pathExists(path.join(repoRoot, "cmd/server/main.go"))) {
    out.entryPoints.add("cmd/server/main.go");
  } else if (await pathExists(path.join(repoRoot, "main.go"))) {
    out.entryPoints.add("main.go");
  }
}

async function gatherFromPython(repoRoot: string, out: MutableRepoContext): Promise<void> {
  const requirements = await readText(path.join(repoRoot, "requirements.txt"));
  const pyproject = await readText(path.join(repoRoot, "pyproject.toml"));
  const combined = [requirements, pyproject].filter(Boolean).join("\n").toLowerCase();

  if (!combined) {
    return;
  }

  out.languages.add("Python");

  if (combined.includes("django")) {
    out.frameworks.add("Django");
  }
  if (combined.includes("flask")) {
    out.frameworks.add("Flask");
  }
  if (combined.includes("fastapi")) {
    out.frameworks.add("FastAPI");
  }
  if (combined.includes("graphene") || combined.includes("ariadne")) {
    out.frameworks.add("GraphQL");
  }

  if (combined.includes("pyjwt") || combined.includes("jwt")) {
    out.authPatterns.add("JWT");
  }
  if (combined.includes("oauth") || combined.includes("authlib")) {
    out.authPatterns.add("OAuth");
  }

  if (combined.includes("bleach")) {
    out.sanitizationLibs.add("bleach");
  }

  if (combined.includes("sqlalchemy")) {
    out.ormOrDb.add("SQLAlchemy");
  }
  if (combined.includes("django")) {
    out.ormOrDb.add("Django ORM");
  }

  if (await pathExists(path.join(repoRoot, "app.py"))) {
    out.entryPoints.add("app.py");
  }
  if (await pathExists(path.join(repoRoot, "main.py"))) {
    out.entryPoints.add("main.py");
  }
}

async function gatherFromCargoToml(repoRoot: string, out: MutableRepoContext): Promise<void> {
  const cargoToml = await readText(path.join(repoRoot, "Cargo.toml"));
  if (!cargoToml) {
    return;
  }

  const lower = cargoToml.toLowerCase();
  out.languages.add("Rust");

  if (lower.includes("actix-web")) {
    out.frameworks.add("Actix Web");
  }
  if (lower.includes("rocket")) {
    out.frameworks.add("Rocket");
  }

  if (lower.includes("jsonwebtoken")) {
    out.authPatterns.add("JWT");
  }
  if (lower.includes("oauth")) {
    out.authPatterns.add("OAuth");
  }

  if (lower.includes("diesel")) {
    out.ormOrDb.add("Diesel");
  }
  if (lower.includes("sqlx")) {
    out.ormOrDb.add("sqlx");
  }

  if (await pathExists(path.join(repoRoot, "src/main.rs"))) {
    out.entryPoints.add("src/main.rs");
  }
}

async function gatherFromNativeBuildSystem(
  repoRoot: string,
  out: MutableRepoContext,
): Promise<void> {
  const cmake = await readText(path.join(repoRoot, "CMakeLists.txt"));
  const makefile = await readText(path.join(repoRoot, "Makefile"));
  const configure = await readText(path.join(repoRoot, "configure.ac"));
  const meson = await readText(path.join(repoRoot, "meson.build"));
  const combined = [cmake, makefile, configure, meson].filter(Boolean).join("\n");

  if (!combined) return;

  const lower = combined.toLowerCase();

  // Detect C/C++ from build system presence
  if (cmake || configure || meson) {
    out.languages.add("C");
    if (lower.includes("cxx") || lower.includes("c++") || lower.includes("cpp")) {
      out.languages.add("C++");
    }
  } else if (makefile) {
    // Makefile alone is ambiguous; check for C/C++ compiler references
    if (/\b(?:gcc|g\+\+|clang|clang\+\+|cc)\b/.test(lower)) {
      out.languages.add("C");
    }
    if (/\b(?:g\+\+|clang\+\+|cxx)\b/.test(lower)) {
      out.languages.add("C++");
    }
  }

  // Detect common native libraries/frameworks
  if (lower.includes("openssl") || lower.includes("libssl")) {
    out.frameworks.add("OpenSSL");
  }
  if (lower.includes("libpcap")) {
    out.frameworks.add("libpcap");
  }

  // Detect entry points
  if (await pathExists(path.join(repoRoot, "src/main.c"))) {
    out.entryPoints.add("src/main.c");
  }
  if (await pathExists(path.join(repoRoot, "src/main.cpp"))) {
    out.entryPoints.add("src/main.cpp");
  }
  if (await pathExists(path.join(repoRoot, "main.c"))) {
    out.entryPoints.add("main.c");
  }
}

function gatherFromPathSignals(signals: PathSignals, out: MutableRepoContext): void {
  if (
    signals.fileSet.has(".env") ||
    signals.fileSet.has(".env.local") ||
    signals.fileSet.has(".env.production")
  ) {
    out.entryPoints.add(".env*");
  }
  if (signals.fileSet.has("docker-compose.yml") || signals.fileSet.has("docker-compose.yaml")) {
    out.entryPoints.add("docker-compose.yml");
  }
  if (signals.fileSet.has("Dockerfile")) {
    out.entryPoints.add("Dockerfile");
  }

  const hasAuthDir = [...signals.dirs].some(
    (dir) => dir.includes("/auth") || dir.startsWith("auth"),
  );
  const hasMiddlewareDir = [...signals.dirs].some(
    (dir) => dir.includes("/middleware") || dir.startsWith("middleware"),
  );

  if (hasAuthDir) {
    out.authPatterns.add("auth-module");
  }
  if (hasMiddlewareDir) {
    out.authPatterns.add("middleware-guards");
  }

  if ([...signals.fileSet].some((file) => file.startsWith("src/pages/api/"))) {
    out.entryPoints.add("src/pages/api/*");
  }
  if ([...signals.fileSet].some((file) => file.startsWith("src/app/api/"))) {
    out.entryPoints.add("src/app/api/*");
  }
  if (signals.fileSet.has("cmd/server/main.go")) {
    out.entryPoints.add("cmd/server/main.go");
  }
}

async function walkRepo(repoRoot: string): Promise<PathSignals> {
  const files: WalkEntry[] = [];
  const fileSet = new Set<string>();
  const dirs = new Set<string>();
  const entries = await walkRepoEntries(repoRoot, {
    maxDepth: MAX_WALK_DEPTH,
    maxEntries: MAX_WALK_ENTRIES,
    ignoredDirs: DEFAULT_IGNORED_DIRS,
  });

  for (const entry of entries) {
    const relPath = normalizeRelPath(entry.relPath);
    if (entry.kind === "dir") {
      dirs.add(relPath);
      continue;
    }

    files.push({ relPath });
    fileSet.add(relPath);
  }

  return { files, fileSet, dirs };
}

async function readJson(filePath: string): Promise<Record<string, unknown> | undefined> {
  const content = await readText(filePath);
  if (!content) {
    return undefined;
  }

  try {
    const parsed = JSON.parse(content);
    if (isRecord(parsed)) {
      return parsed;
    }
  } catch {
    return undefined;
  }

  return undefined;
}

async function readText(filePath: string): Promise<string | undefined> {
  try {
    return await readFile(filePath, "utf-8");
  } catch {
    return undefined;
  }
}

function extractDependencyNames(pkg: Record<string, unknown>): Set<string> {
  const names = new Set<string>();
  collectDependencyKeys(names, pkg["dependencies"]);
  collectDependencyKeys(names, pkg["devDependencies"]);
  collectDependencyKeys(names, pkg["peerDependencies"]);
  collectDependencyKeys(names, pkg["optionalDependencies"]);
  return names;
}

function collectDependencyKeys(target: Set<string>, raw: unknown): void {
  if (!isRecord(raw)) {
    return;
  }

  for (const key of Object.keys(raw)) {
    target.add(key.toLowerCase());
  }
}

function maybeAdd(
  target: Set<string>,
  dependencies: Set<string>,
  keys: string[],
  label: string,
): void {
  if (keys.some((key) => dependencies.has(key))) {
    target.add(label);
  }
}

async function pathExists(filePath: string): Promise<boolean> {
  try {
    await stat(filePath);
    return true;
  } catch {
    return false;
  }
}

function normalizeRelPath(relPath: string): string {
  return relPath.split(path.sep).join("/").replace(/^\.\//, "");
}

function sortValues(values: Set<string>): string[] {
  return [...values].sort((a, b) => a.localeCompare(b));
}
