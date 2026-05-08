import type { KnowledgeModule } from "../types.js";

export const sqliModule: KnowledgeModule = {
  id: "sqli",
  cwes: ["CWE-89"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    {
      pattern: "String concatenation in SQL queries",
      why: "Direct injection vector when user input is concatenated",
      severity: "ERROR",
    },
    {
      pattern: "Template literals in SQL without parameterization",
      why: "Interpolated values bypass prepared statement protection",
      severity: "ERROR",
    },
    {
      pattern: "Dynamic SQL in stored procedures",
      why: "Server-side dynamic SQL is still injectable",
      severity: "WARNING",
    },
    {
      pattern: "ORM raw query methods",
      why: "Raw/literal query APIs bypass ORM sanitization",
      severity: "WARNING",
    },
    {
      pattern: "LIKE clause with unescaped wildcards",
      why: "% and _ characters enable data exfiltration via inference",
      severity: "INFO",
    },
  ],
  safePatterns: [
    {
      pattern: "Parameterized queries with ? or $N placeholders",
      why: "Parameters are bound separately from SQL structure",
    },
    {
      pattern: "ORM model methods (find, where, create)",
      why: "ORM generates parameterized queries automatically",
    },
    {
      pattern: "Stored procedures with typed parameters",
      why: "Typed params prevent SQL structure modification",
    },
  ],
  bypassTechniques: [
    "Comment injection (/**/, --, #) to break query structure",
    "Case variation (SeLeCt, UnIoN) to bypass keyword filters",
    "URL encoding (%27 for quote, %2527 for double-encoding)",
    "Numeric context — unquoted integers skip string-based filters",
    "Wide-byte injection (GBK/BIG5 encoding: %bf%27 → valid multibyte + quote)",
    "Nested queries and UNION-based extraction",
    "Time-based blind injection (SLEEP, BENCHMARK, pg_sleep)",
    "Boolean-based blind injection with conditional responses",
  ],
  detectionKeywords: [
    "query",
    "execute",
    "exec",
    "raw",
    "sql",
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "knex.raw",
    "sequelize.query",
    "prisma.$queryRaw",
    "db.execute",
  ],
  fixExamples: [
    {
      language: "JavaScript",
      before: "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
      after: "db.query('SELECT * FROM users WHERE id = ?', [req.params.id])",
      explanation: "Use parameterized queries instead of string interpolation",
    },
  ],
  tags: ["injection", "database", "sql"],
};
