/**
 * Shared types and constants for the deep-semantic analysis pipeline.
 */

/** CWE classes relevant to deep semantic / memory-safety bugs. */
export const DEEP_SEMANTIC_CWE_MENU = [
  { id: "CWE-190", name: "Integer Overflow/Wraparound", exemplar: "OpenBSD TCP SACK" },
  { id: "CWE-191", name: "Integer Underflow", exemplar: "signed subtraction producing negative lengths" },
  { id: "CWE-681", name: "Incorrect Numeric Type Conversion", exemplar: "signed/unsigned comparison" },
  { id: "CWE-787", name: "Out-of-Bounds Write", exemplar: "FFmpeg H.264 sentinel collision" },
  { id: "CWE-125", name: "Out-of-Bounds Read", exemplar: "parser overreads" },
  { id: "CWE-476", name: "NULL Pointer Dereference", exemplar: "OpenBSD SACK dereference" },
  { id: "CWE-119", name: "Buffer Overflow (generic)", exemplar: "FreeBSD NFS stack overflow" },
  { id: "CWE-416", name: "Use After Free", exemplar: "protocol state machine bugs" },
  { id: "CWE-672", name: "Operation on Expired Resource", exemplar: "dangling references in state machines" },
  { id: "CWE-704", name: "Incorrect Type Conversion", exemplar: "Rust unsafe FFI type confusion" },
  { id: "CWE-693", name: "Protection Mechanism Failure", exemplar: "missing stack canary" },
] as const;

/** Languages where deep semantic analysis is applicable. */
export const DEEP_SEMANTIC_LANGUAGES = new Set([
  "c", "c++", "cpp", "rust", "go", "golang",
]);

export function isDeepSemanticLanguage(lang: string): boolean {
  return DEEP_SEMANTIC_LANGUAGES.has(lang.toLowerCase());
}
