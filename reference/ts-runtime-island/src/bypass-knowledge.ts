/** Bypass techniques for a specific vulnerability category. */
export interface BypassEntry {
  category: string;
  techniques: string[];
}

const BYPASS_MAP: Record<string, BypassEntry> = {
  "89": {
    category: "SQL Injection",
    techniques: [
      "Comment injection (/**/, --, #) to break query structure",
      "Case variation (SeLeCt, UnIoN) to bypass keyword filters",
      "URL encoding (%27 for quote, %2527 for double-encoding)",
      "Numeric context — unquoted integers skip string-based filters",
      "Wide-byte injection (GBK/BIG5 encoding: %bf%27 → valid multibyte + quote)",
      "Nested queries and UNION-based extraction",
      "Time-based blind injection (SLEEP, BENCHMARK, pg_sleep)",
      "Boolean-based blind injection with conditional responses",
    ],
  },
  "79": {
    category: "Cross-Site Scripting (XSS)",
    techniques: [
      "Tag mutation (<ScRiPt>, <img/src=x>, <svg/onload=>) to bypass tag filters",
      "Event handlers (onerror, onload, onfocus, onmouseover) as script-free vectors",
      "HTML entity encoding (&#x3C;script&#x3E;, &#60;) to bypass text filters",
      "JavaScript Unicode escapes (\\u0061lert) in JS contexts",
      "Protocol handlers (javascript:, data:text/html) in href/src attributes",
      "Template literal injection in JS contexts (${expression})",
      "DOM-based XSS via document.location, innerHTML, eval sinks",
      "SVG/MathML namespace confusion for filter bypass",
    ],
  },
  "78": {
    category: "OS Command Injection",
    techniques: [
      "Command chaining with ;, |, ||, &&, and newline characters",
      "Command substitution via $() and backticks",
      "Whitespace bypass using ${IFS}, $IFS, {cat,/etc/passwd}, tab characters",
      "Keyword bypass with ca\\t, c$@at, /???/c?t, string concatenation",
      "Hex/octal encoding (\\x63\\x61\\x74 for 'cat')",
      "Environment variable abuse ($PATH manipulation, $HOME injection)",
    ],
  },
  "918": {
    category: "Server-Side Request Forgery (SSRF)",
    techniques: [
      "Alternative IP representations (0x7f000001, 2130706433, 017700000001 for 127.0.0.1)",
      "DNS rebinding — domain resolves to internal IP after initial check",
      "HTTP redirect chains from allowed domain to internal target",
      "IPv6 representations ([::1], [::ffff:127.0.0.1], [0:0:0:0:0:ffff:7f00:1])",
      "Protocol smuggling via gopher://, dict://, file:// handlers",
      "URL parsing discrepancies between validator and HTTP client",
      "Cloud metadata endpoints (169.254.169.254, metadata.google.internal)",
    ],
  },
  "434": {
    category: "Unrestricted File Upload",
    techniques: [
      "Null byte truncation (shell.php%00.jpg) on older systems",
      "Double extensions (shell.php.xxx) exploiting parser discrepancies",
      "Content-Type spoofing (image/jpeg header with PHP body)",
      "Parser discrepancies (IIS 6.0 semicolon: file.asp;.jpg, Apache: file.php.xxx)",
      "Magic bytes prepend (GIF89a header before PHP code)",
      "Polyglot files (valid image that also executes as code)",
      "Race condition between upload and validation",
    ],
  },
  "22": {
    category: "Path Traversal",
    techniques: [
      "Encoded traversal sequences (%2e%2e%2f, %2e%2e/, ..%2f)",
      "Double-encoding (%252e%252e%252f for ../ after double decode)",
      "Null byte truncation (%00) to strip file extension checks",
      "Windows-specific backslash traversal (..\\..\\)",
      "Unicode normalization bypass (%c0%ae for '.' in overlong UTF-8)",
      "Symlink following when file operations don't check link targets",
    ],
  },
  "287": {
    category: "Authentication Bypass",
    techniques: [
      "IDOR via sequential/predictable ID enumeration",
      "Step-skipping in multi-step auth flows (jump to step 3 directly)",
      "Verification code leaked in response body or headers",
      "Universal/default codes (0000, 1234, 123456) in OTP implementations",
      "Type juggling (sending array instead of string, null vs empty)",
      "JWT algorithm confusion (none, HS256 vs RS256)",
      "Session fixation / token reuse across privilege boundaries",
    ],
  },
  "862": {
    category: "Missing Authorization",
    techniques: [
      "IDOR via sequential/predictable ID enumeration",
      "Step-skipping in multi-step auth flows",
      "Forced browsing to admin/privileged endpoints",
      "Parameter tampering (role=admin, isAdmin=true)",
      "HTTP method override (X-HTTP-Method-Override, _method parameter)",
      "Mass assignment / object injection to set privileged fields",
    ],
  },
};

// Map common rule ID patterns to CWE numbers for lookup
const RULE_TO_CWE: Record<string, string> = {
  sqli: "89",
  "sql-injection": "89",
  sql_injection: "89",
  xss: "79",
  "cross-site-scripting": "79",
  "command-injection": "78",
  "os-command": "78",
  "cmd-injection": "78",
  ssrf: "918",
  "server-side-request": "918",
  "file-upload": "434",
  "unrestricted-upload": "434",
  "path-traversal": "22",
  "directory-traversal": "22",
  lfi: "22",
  "auth-bypass": "287",
  authentication: "287",
  "missing-auth": "862",
  "broken-access": "862",
  idor: "862",
};

/**
 * Look up bypass techniques for a finding based on its CWE list and/or rule ID.
 * Returns the most relevant bypass entry, or undefined if no match.
 */
export function getBypassKnowledge(cwe: string[], ruleId: string): BypassEntry | undefined {
  // Try CWE numbers first (most precise)
  for (const cweId of cwe) {
    const normalized = cweId.replace(/^CWE-/i, "").trim();
    if (BYPASS_MAP[normalized]) {
      return BYPASS_MAP[normalized];
    }
  }

  // Fall back to rule ID pattern matching
  const lowerRuleId = ruleId.toLowerCase();
  for (const [pattern, cweNum] of Object.entries(RULE_TO_CWE)) {
    if (lowerRuleId.includes(pattern)) {
      return BYPASS_MAP[cweNum];
    }
  }

  return undefined;
}

/**
 * Format bypass knowledge into prompt lines for injection into verification prompts.
 */
export function formatBypassForPrompt(entry: BypassEntry): string[] {
  return [
    `## Category-Specific Bypass Techniques (${entry.category})`,
    "Before concluding not-exploitable, verify the application is NOT vulnerable to these known bypass techniques:",
    ...entry.techniques.map((t) => `- ${t}`),
  ];
}
