/**
 * Kuzushi commit message conventions.
 *
 * Extends @commitlint/config-conventional with a type enum that matches what
 * this repository actually uses in its history. Notably, `merge:` is non-
 * standard but appears in recent merges of parallel agent work; we legitimize
 * it rather than ban or rewrite it.
 *
 * See docs/devex/05-conventions-assessment.md for rationale and escape hatches.
 */
export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    // Loosen the subject-case rule — we have many past commits that use
    // proper nouns, acronyms, or PascalCase in subjects (e.g. "SQLite"),
    // and case-pedantry is a classic source of friction.
    "subject-case": [0],

    // Allow slightly longer headers than the 72-char conventional default.
    // Repo owner writes descriptive subjects; 100 is a sane cap.
    "header-max-length": [2, "always", 100],

    // Type enum: authoritative list for this repo. Keep in sync with
    // .gitmessage and the PR template.
    "type-enum": [
      2,
      "always",
      [
        "feat",
        "fix",
        "chore",
        "perf",
        "refactor",
        "docs",
        "test",
        "style",
        "ci",
        "build",
        "revert",
        "merge",
      ],
    ],
  },
};
