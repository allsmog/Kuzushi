import type { KnowledgeModule } from "../types.js";

export const pathTraversalModule: KnowledgeModule = {
  id: "path-traversal",
  cwes: ["CWE-22"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    {
      pattern: "File path from user input without normalization",
      why: "../ sequences escape intended directory",
      severity: "ERROR",
    },
    {
      pattern: "path.join() with user input without validation",
      why: "path.join preserves ../ components",
      severity: "ERROR",
    },
    {
      pattern: "Static file serving with user-controlled path",
      why: "Traversal can access files outside webroot",
      severity: "ERROR",
    },
    {
      pattern: "Archive extraction without path validation",
      why: "Zip slip — archive entries with ../ paths",
      severity: "ERROR",
    },
  ],
  safePatterns: [
    {
      pattern: "path.resolve() + startsWith() check",
      why: "Resolves to absolute path, then validates prefix",
    },
    { pattern: "chroot/sandbox for file operations", why: "OS-level containment prevents escape" },
    { pattern: "Basename extraction before path construction", why: "Strips directory components" },
  ],
  bypassTechniques: [
    "Encoded traversal sequences (%2e%2e%2f, %2e%2e/, ..%2f)",
    "Double-encoding (%252e%252e%252f for ../ after double decode)",
    "Null byte truncation (%00) to strip file extension checks",
    "Windows-specific backslash traversal (..\\..\\)",
    "Unicode normalization bypass (overlong UTF-8 sequences)",
    "Symlink following when file operations don't check link targets",
  ],
  detectionKeywords: [
    "readFile",
    "writeFile",
    "createReadStream",
    "open",
    "stat",
    "path.join",
    "path.resolve",
    "fs.access",
    "sendFile",
    "os.path.join",
    "shutil",
    "zipfile.extractall",
  ],
  fixExamples: [
    {
      language: "JavaScript",
      before: "fs.readFile(path.join(base, req.query.file))",
      after:
        "const resolved = path.resolve(base, req.query.file); if (!resolved.startsWith(path.resolve(base))) throw new Error('path traversal'); fs.readFile(resolved)",
      explanation: "Resolve to absolute path and verify it starts with the intended base directory",
    },
  ],
  tags: ["path-traversal", "file", "directory", "lfi"],
};
