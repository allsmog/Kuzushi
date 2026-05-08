import type { KnowledgeModule } from "../types.js";

export const ssrfModule: KnowledgeModule = {
  id: "ssrf",
  cwes: ["CWE-918"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    {
      pattern: "User-controlled URL passed to HTTP client",
      why: "Direct SSRF when URL comes from request params/body",
      severity: "ERROR",
    },
    {
      pattern: "URL constructed from user input without allowlist",
      why: "Attacker can target internal services",
      severity: "ERROR",
    },
    {
      pattern: "HTTP client following redirects with user URL",
      why: "Redirect chains bypass hostname validation",
      severity: "WARNING",
    },
    {
      pattern: "Cloud metadata endpoint accessible via SSRF",
      why: "169.254.169.254 exposes credentials and instance metadata",
      severity: "ERROR",
    },
    {
      pattern: "DNS resolution before validation",
      why: "DNS rebinding can change IP after check",
      severity: "WARNING",
    },
  ],
  safePatterns: [
    { pattern: "Hardcoded internal service URLs", why: "No user control over destination" },
    {
      pattern: "URL allowlist validation against hostname",
      why: "Restricts destinations to known-good hosts",
    },
    {
      pattern: "IP address validation rejecting private ranges",
      why: "Blocks access to internal network",
    },
    { pattern: "Redirect following disabled", why: "Prevents redirect-based bypass" },
  ],
  bypassTechniques: [
    "Alternative IP representations (0x7f000001, 2130706433, 017700000001 for 127.0.0.1)",
    "DNS rebinding — domain resolves to internal IP after initial check",
    "HTTP redirect chains from allowed domain to internal target",
    "IPv6 representations ([::1], [::ffff:127.0.0.1], [0:0:0:0:0:ffff:7f00:1])",
    "Protocol smuggling via gopher://, dict://, file:// handlers",
    "URL parsing discrepancies between validator and HTTP client",
    "Cloud metadata endpoints (169.254.169.254, metadata.google.internal)",
  ],
  detectionKeywords: [
    "fetch",
    "axios",
    "http.get",
    "http.request",
    "urllib",
    "requests.get",
    "HttpClient",
    "curl",
    "wget",
    "url.parse",
    "new URL",
  ],
  fixExamples: [
    {
      language: "JavaScript",
      before: "const resp = await fetch(req.query.url)",
      after:
        "const parsed = new URL(req.query.url); if (!ALLOWED_HOSTS.has(parsed.hostname)) throw new Error('blocked'); const resp = await fetch(parsed.href, { redirect: 'manual' })",
      explanation: "Validate URL hostname against allowlist and disable redirect following",
    },
  ],
  tags: ["ssrf", "network", "server-side"],
};
