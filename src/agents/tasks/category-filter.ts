import type { FileIndex, RepoContext } from "../../types.js";

export interface CategoryRelevance {
  id: string;
  always?: boolean;
  languages?: string[];
  frameworks?: string[];
  requiresAuth?: boolean;
  requiresWebFramework?: boolean;
  ormOrDbPattern?: RegExp;
  fileTreePattern?: RegExp;
}

export interface CategoryBlock {
  id: string;
  lines: string[];
}

const LANGUAGE_ALIASES: Record<string, string> = {
  js: "javascript",
  jsx: "javascript",
  ts: "typescript",
  tsx: "typescript",
  py: "python",
  golang: "go",
  kt: "kotlin",
  rb: "ruby",
  csharp: "c#",
  "c sharp": "c#",
  cpp: "c++",
};

export function normalizeLanguageName(lang: string): string {
  const lower = lang.toLowerCase().trim();
  return LANGUAGE_ALIASES[lower] ?? lower;
}

export const WEB_FRAMEWORKS = new Set([
  "express",
  "koa",
  "fastify",
  "hapi",
  "django",
  "flask",
  "fastapi",
  "rails",
  "spring",
  "asp.net",
  "aspnet",
  "gin",
  "echo",
  "fiber",
  "laravel",
  "symfony",
  "phoenix",
]);

export const SQL_DB_PATTERN =
  /sql|postgres|mysql|sqlite|prisma|sequelize|typeorm|knex|hibernate|sqlalchemy|activerecord|diesel/i;

export function filterCategories(
  mappings: CategoryRelevance[],
  repoContext: RepoContext | undefined,
  fileIndex?: FileIndex,
): Set<string> {
  if (!repoContext) return new Set(mappings.map((m) => m.id));

  const repoLangs = new Set(repoContext.languages.map(normalizeLanguageName));
  const repoFrameworks = new Set(repoContext.frameworks.map((f) => f.toLowerCase().trim()));
  const hasAuth = repoContext.authPatterns.length > 0;
  const hasWebFramework = repoContext.frameworks.some((f) =>
    WEB_FRAMEWORKS.has(f.toLowerCase().trim()),
  );
  const filePaths = fileIndex?.tree.map((f) => f.path) ?? [];

  const included = new Set<string>();

  for (const mapping of mappings) {
    if (mapping.always) {
      included.add(mapping.id);
      continue;
    }

    let match = false;

    if (mapping.languages?.some((l) => repoLangs.has(normalizeLanguageName(l)))) {
      match = true;
    }

    if (
      !match &&
      mapping.frameworks?.some((f) =>
        [...repoFrameworks].some((rf) => rf.includes(f.toLowerCase())),
      )
    ) {
      match = true;
    }

    if (!match && mapping.requiresAuth && hasAuth) {
      match = true;
    }

    if (!match && mapping.requiresWebFramework && hasWebFramework) {
      match = true;
    }

    if (
      !match &&
      mapping.ormOrDbPattern &&
      repoContext.ormOrDb.some((db) => mapping.ormOrDbPattern!.test(db))
    ) {
      match = true;
    }

    if (
      !match &&
      mapping.fileTreePattern &&
      filePaths.some((f) => mapping.fileTreePattern!.test(f))
    ) {
      match = true;
    }

    if (match) {
      included.add(mapping.id);
    }
  }

  return included;
}

export function filterBlocks(blocks: CategoryBlock[], included: Set<string>): string[] {
  return blocks.filter((b) => included.has(b.id)).flatMap((b) => b.lines);
}

export const CATEGORY_SCOPE_HEADER = [
  "## Category scope",
  "The categories below have been pre-filtered based on this repository's languages,",
  "frameworks, and infrastructure. Focus exclusively on the listed categories.",
  "Do not investigate vulnerability classes not listed — they are not applicable.",
  "",
];
