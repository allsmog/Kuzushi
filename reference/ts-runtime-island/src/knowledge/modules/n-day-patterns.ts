import type { KnowledgeModule } from "../types.js";

/**
 * Fix-shape archetypes extracted from historical CVE patches.
 *
 * Used by `ndiff:extract-fix-pattern` to bias the LLM toward recognized
 * fix shapes, and by `ndiff:hunt-variants` to narrow the pre-patch search.
 */
export const nDayPatternsModule: KnowledgeModule = {
  id: "n-day-patterns",
  cwes: [
    "CWE-20",
    "CWE-22",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-125",
    "CWE-190",
    "CWE-191",
    "CWE-287",
    "CWE-362",
    "CWE-369",
    "CWE-416",
    "CWE-502",
    "CWE-611",
    "CWE-787",
    "CWE-798",
    "CWE-863",
    "CWE-918",
  ],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    {
      pattern: "Missing bounds check before indexed read or write",
      why: "Classic CVE fix shape: diff adds `if (idx >= len) return ERROR;` before access.",
      severity: "ERROR",
    },
    {
      pattern: "Missing signed/unsigned promotion check on length field",
      why: "Patch adds `if (len < 0 || len > cap)` — pre-patch trusted an attacker-controlled length.",
      severity: "ERROR",
    },
    {
      pattern: "eval / exec / unserialize removed or replaced with safe alternative",
      why: "Fix commit swaps a dynamic code evaluation primitive for a constrained parser.",
      severity: "ERROR",
    },
    {
      pattern: "Non-constant-time comparison on secret material",
      why: "Fix replaces `==`/`strcmp` with `crypto_equals`/`subtle.timingSafeEqual`.",
      severity: "WARNING",
    },
    {
      pattern: "Missing permission check before privileged operation",
      why: "Fix adds `if (!user.isAdmin)` or equivalent authz guard.",
      severity: "ERROR",
    },
    {
      pattern: "Missing origin / hostname / allowlist check on outbound URL",
      why: "Fix adds SSRF guard before `fetch`/`requests.get`.",
      severity: "ERROR",
    },
    {
      pattern: "Missing XML external entity (XXE) disable on parser",
      why: "Fix sets `disallow-doctype-decl`/`resolveExternalGeneralEntities=false` on the parser.",
      severity: "ERROR",
    },
    {
      pattern: "Missing integer overflow check in allocation size",
      why: "Fix uses checked arithmetic (`__builtin_mul_overflow`, `Math.checkedMul`) before alloc.",
      severity: "ERROR",
    },
    {
      pattern: "Missing null / empty check before dereference",
      why: "Fix adds guard against empty or null input from untrusted source.",
      severity: "WARNING",
    },
    {
      pattern: "Missing canonical path normalization before filesystem access",
      why: "Fix adds `realpath`/`path.resolve` + prefix check to block traversal.",
      severity: "ERROR",
    },
  ],
  safePatterns: [
    {
      pattern: "Size validation before memcpy / copy_to_user",
      why: "Checks src length against destination capacity prior to copy.",
    },
    {
      pattern: "Allowlist-based input validation",
      why: "Rejects inputs outside a known safe set instead of denylisting.",
    },
    {
      pattern: "Parameterized/prepared query with bound inputs",
      why: "Separates SQL structure from data — survives most injection attempts.",
    },
    {
      pattern: "Canonical path resolved and prefix-checked against base dir",
      why: "Normalizes path before filesystem access and confirms containment.",
    },
    {
      pattern: "Rate-limited and authenticated API endpoint",
      why: "Blocks brute-force and automated abuse at the perimeter.",
    },
  ],
  bypassTechniques: [
    "Unicode normalization can cause a pre-patch variant to bypass an added naive string check.",
    "Second-order injection (write-then-read) may reach sinks that the added guard did not cover.",
    "Nested structures (e.g. JSON within JSON) often skip length validation at the outer layer only.",
    "Signed-to-unsigned conversion at a different call site may still overflow even after one site is patched.",
    "Recursive parsers: fixing one depth-check site may leave sibling parse paths vulnerable.",
  ],
  detectionKeywords: [
    "bounds",
    "overflow",
    "length",
    "size",
    "capacity",
    "if (",
    "assert",
    "check",
    "validate",
    "sanitize",
    "authorize",
    "permission",
    "allowlist",
    "whitelist",
    "normalize",
    "canonical",
    "realpath",
    "resolve",
    "escape",
    "eval",
    "exec",
    "unserialize",
    "yaml.load",
    "Marshal.load",
    "pickle.loads",
    "memcpy",
    "strcpy",
    "sprintf",
  ],
  fixExamples: [
    {
      language: "c",
      before: "memcpy(dst, src, len);",
      after: "if (len > sizeof(dst)) return -EINVAL;\nmemcpy(dst, src, len);",
      explanation: "Bounds check before copy — the canonical fix shape for CWE-787/125.",
    },
    {
      language: "python",
      before: "import yaml\nconfig = yaml.load(user_input)",
      after: "import yaml\nconfig = yaml.safe_load(user_input)",
      explanation:
        "Replace unsafe YAML loader with safe alternative (CWE-502) — fix shape is a single-symbol swap.",
    },
    {
      language: "javascript",
      before: "if (token === userToken) return true;",
      after:
        "const a = Buffer.from(token);\nconst b = Buffer.from(userToken);\nif (a.length !== b.length) return false;\nreturn crypto.timingSafeEqual(a, b);",
      explanation:
        "Timing-safe comparison (CWE-208) — `===` leaks secret length and prefix timing.",
    },
    {
      language: "go",
      before: "data, _ := os.ReadFile(filepath.Join(base, name))",
      after:
        'full := filepath.Clean(filepath.Join(base, name))\nif !strings.HasPrefix(full, base) { return nil, errors.New("traversal") }\ndata, _ := os.ReadFile(full)',
      explanation:
        "Canonicalize + containment check (CWE-22). Classic n-day pattern across Go services.",
    },
  ],
  tags: [
    "n-day",
    "cve",
    "patch-diff",
    "variant-analysis",
    "fix-shape",
    "bounds-check",
    "input-validation",
  ],
};
