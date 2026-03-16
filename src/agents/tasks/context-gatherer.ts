import { readdir, readFile, stat } from "node:fs/promises";
import type { Dirent } from "node:fs";
import path from "node:path";
import type { ScanOpts, RepoContext } from "../../types.js";
import { isRecord } from "../../utils.js";
import type { AgentTask } from "../types.js";

const MAX_WALK_DEPTH = 5;
const MAX_WALK_ENTRIES = 4000;
const IGNORED_DIRS = new Set([
  ".git",
  ".kuzushi",
  "node_modules",
  "dist",
  "coverage",
  "vendor",
  "target",
  "build",
  ".next",
]);

interface MutableRepoContext {
  languages: Set<string>;
  frameworks: Set<string>;
  authPatterns: Set<string>;
  sanitizationLibs: Set<string>;
  ormOrDb: Set<string>;
  entryPoints: Set<string>;
}

interface PathSignals {
  files: Set<string>;
  dirs: Set<string>;
}

/**
 * Deterministic, non-AI pre-scan repository context gathering task.
 */
export const contextGathererTask: AgentTask<ScanOpts, RepoContext> = {
  id: "context-gatherer",
  displayName: "Context Gatherer",
  outputKind: "custom",
  dependsOn: [],
  async run(_input, context): Promise<RepoContext> {
    const aggregate = createMutableRepoContext();

    await Promise.all([
      gatherFromPackageJson(context.repoRoot, aggregate),
      gatherFromGoMod(context.repoRoot, aggregate),
      gatherFromPython(context.repoRoot, aggregate),
      gatherFromCargoToml(context.repoRoot, aggregate),
    ]);

    const pathSignals = await walkRepo(context.repoRoot);
    gatherFromPathSignals(pathSignals, aggregate);

    return {
      languages: sortValues(aggregate.languages),
      frameworks: sortValues(aggregate.frameworks),
      authPatterns: sortValues(aggregate.authPatterns),
      sanitizationLibs: sortValues(aggregate.sanitizationLibs),
      ormOrDb: sortValues(aggregate.ormOrDb),
      entryPoints: sortValues(aggregate.entryPoints),
    };
  },
};

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
  maybeAdd(out.frameworks, depNames, ["graphql", "@apollo/server", "apollo-server", "mercurius"], "GraphQL");

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

function gatherFromPathSignals(signals: PathSignals, out: MutableRepoContext): void {
  if (signals.files.has(".env") || signals.files.has(".env.local") || signals.files.has(".env.production")) {
    out.entryPoints.add(".env*");
  }
  if (signals.files.has("docker-compose.yml") || signals.files.has("docker-compose.yaml")) {
    out.entryPoints.add("docker-compose.yml");
  }
  if (signals.files.has("Dockerfile")) {
    out.entryPoints.add("Dockerfile");
  }

  const hasAuthDir = [...signals.dirs].some((dir) => dir.includes("/auth") || dir.startsWith("auth"));
  const hasMiddlewareDir = [...signals.dirs].some(
    (dir) => dir.includes("/middleware") || dir.startsWith("middleware"),
  );

  if (hasAuthDir) {
    out.authPatterns.add("auth-module");
  }
  if (hasMiddlewareDir) {
    out.authPatterns.add("middleware-guards");
  }

  if ([...signals.files].some((file) => file.startsWith("src/pages/api/"))) {
    out.entryPoints.add("src/pages/api/*");
  }
  if ([...signals.files].some((file) => file.startsWith("src/app/api/"))) {
    out.entryPoints.add("src/app/api/*");
  }
  if (signals.files.has("cmd/server/main.go")) {
    out.entryPoints.add("cmd/server/main.go");
  }
}

async function walkRepo(repoRoot: string): Promise<PathSignals> {
  const files = new Set<string>();
  const dirs = new Set<string>();
  const stack: Array<{ relDir: string; depth: number }> = [{ relDir: "", depth: 0 }];
  let visited = 0;

  while (stack.length > 0 && visited < MAX_WALK_ENTRIES) {
    const next = stack.pop();
    if (!next) {
      break;
    }

    const absDir = path.join(repoRoot, next.relDir);
    let entries: Dirent[];
    try {
      entries = await readdir(absDir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (visited >= MAX_WALK_ENTRIES) {
        break;
      }

      const relPath = normalizeRelPath(path.join(next.relDir, entry.name));
      visited += 1;

      if (entry.isDirectory()) {
        dirs.add(relPath);

        if (next.depth >= MAX_WALK_DEPTH || IGNORED_DIRS.has(entry.name)) {
          continue;
        }

        stack.push({
          relDir: relPath,
          depth: next.depth + 1,
        });
        continue;
      }

      if (entry.isFile()) {
        files.add(relPath);
      }
    }
  }

  return { files, dirs };
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

function maybeAdd(target: Set<string>, dependencies: Set<string>, keys: string[], label: string): void {
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
