import type { TaintAnalysisPassDefinition } from "./types.js";

interface KevVulnerability {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  shortDescription?: string;
  cwes?: string | string[];
}

interface KevResponse {
  vulnerabilities?: KevVulnerability[];
}

interface NvdReference {
  url?: string;
}

interface NvdWeaknessDescription {
  value?: string;
}

interface NvdWeakness {
  description?: NvdWeaknessDescription[];
}

interface NvdCve {
  id?: string;
  descriptions?: Array<{ lang?: string; value?: string }>;
  weaknesses?: NvdWeakness[];
  references?: NvdReference[];
}

interface NvdVulnerability {
  cve?: NvdCve;
}

interface NvdResponse {
  vulnerabilities?: NvdVulnerability[];
}

export interface TiReference {
  source: "cisa-kev" | "nvd";
  id: string;
  url: string;
  title: string;
}

export interface TiPriorCwe {
  cwe: string;
  focus: string;
  exploitationStory: string;
  sourceArchetypes: string[];
  sinkArchetypes: string[];
  sanitizers: string[];
  references: TiReference[];
  tiWeight: "HIGH" | "MEDIUM" | "LOW";
  highPriority: string[];
  commonFalsePositives: string[];
  oftenExploitable: string[];
}

export interface TiPriorDocument {
  version: string;
  generatedAt: string;
  mode: "live-required";
  degraded: boolean;
  errors: string[];
  cwes: TiPriorCwe[];
}

export interface BuildTiPriorOptions {
  passes: TaintAnalysisPassDefinition[];
  timeoutMs: number;
}

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const NVD_URL_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

interface FocusTemplate {
  exploitationStory: string;
  sourceArchetypes: string[];
  sinkArchetypes: string[];
  sanitizers: string[];
  highPriority: string[];
  commonFalsePositives: string[];
  oftenExploitable: string[];
}

const FOCUS_TEMPLATES: Record<string, FocusTemplate> = {
  path_traversal: {
    exploitationStory:
      "Attackers pivot from path input handling into file APIs to escape intended directories and access sensitive files.",
    sourceArchetypes: [
      "HTTP path/query params",
      "archive entry names",
      "CLI path args",
      "message payload path fields",
    ],
    sinkArchetypes: [
      "file open/read/write",
      "archive extraction destination",
      "path join before file operations",
    ],
    sanitizers: [
      "realpath canonicalization + base-dir allowlist",
      "basename-only restrictions",
      "explicit traversal token rejection",
    ],
    highPriority: [
      "file-serving endpoints",
      "download/export handlers",
      "zip/tar extraction routines",
    ],
    commonFalsePositives: [
      "paths constrained to static config",
      "strict base-dir containment checks",
      "test fixture file handling",
    ],
    oftenExploitable: [
      "user path concatenated into filesystem calls",
      "archive extraction without path normalization",
    ],
  },
  command_injection: {
    exploitationStory:
      "Untrusted data reaches shell/process execution APIs and changes command semantics or command targets.",
    sourceArchetypes: [
      "HTTP params/body",
      "webhook payload fields",
      "CLI args",
      "database-stored command fragments",
    ],
    sinkArchetypes: [
      "shell execution APIs",
      "process spawn with shell mode",
      "command string builders",
    ],
    sanitizers: [
      "argument-list APIs with shell disabled",
      "strict command allowlists",
      "tokenized command builders",
    ],
    highPriority: [
      "wrapper utilities around exec/spawn",
      "build/deploy endpoints",
      "admin tooling APIs",
    ],
    commonFalsePositives: [
      "constant command strings",
      "shell disabled + strict arg validation",
      "test utilities invoking shell",
    ],
    oftenExploitable: ["`sh -c`/`bash -c` with user input", "concatenated command strings"],
  },
  ssrf: {
    exploitationStory:
      "Attacker-controlled URLs are fetched by server-side clients, enabling internal network probing and credential access.",
    sourceArchetypes: [
      "URL params",
      "webhook target fields",
      "tenant-configurable endpoints",
      "import URL fields",
    ],
    sinkArchetypes: ["HTTP request clients", "URL fetch helpers", "proxy/forwarding utilities"],
    sanitizers: [
      "scheme/domain allowlists",
      "private IP/range blocking",
      "DNS + redirect validation",
    ],
    highPriority: ["proxy endpoints", "metadata fetchers", "webhook dispatch code"],
    commonFalsePositives: [
      "hardcoded trusted endpoints",
      "strict hostname allowlists",
      "OAuth discovery calls with static URLs",
    ],
    oftenExploitable: [
      "raw URL passthrough to fetchers",
      "redirect-following clients without target validation",
    ],
  },
  code_injection: {
    exploitationStory:
      "User-influenced content reaches dynamic evaluation or compilation APIs, allowing arbitrary code execution.",
    sourceArchetypes: [
      "template snippets",
      "expression fields",
      "plugin/script payloads",
      "deserialized code-like content",
    ],
    sinkArchetypes: [
      "eval/exec",
      "dynamic compilation APIs",
      "template engines in executable mode",
    ],
    sanitizers: [
      "allowlisted expression DSLs",
      "sandboxed interpreters",
      "strict parser-based validation",
    ],
    highPriority: ["plugin systems", "custom rule engines", "runtime script features"],
    commonFalsePositives: [
      "constant expression evaluation",
      "safe parser-only evaluation",
      "tests validating eval behavior",
    ],
    oftenExploitable: ["eval over request/DB strings", "dynamic function constructors"],
  },
  sql_injection: {
    exploitationStory:
      "Untrusted strings are interpolated into SQL and executed, enabling data exfiltration, tampering, or privilege escalation.",
    sourceArchetypes: [
      "search/filter params",
      "sort/order fields",
      "bulk import metadata",
      "API request bodies",
    ],
    sinkArchetypes: [
      "raw SQL execute APIs",
      "ORM raw query escape hatches",
      "query builder string interpolation paths",
    ],
    sanitizers: [
      "prepared statements",
      "parameter binding",
      "strict query templates with allowlisted fragments",
    ],
    highPriority: ["raw SQL helper modules", "reporting endpoints", "dynamic where/order builders"],
    commonFalsePositives: [
      "fully parameterized queries",
      "constant SQL statements",
      "migrations using static SQL",
    ],
    oftenExploitable: ["string-concatenated SQL", "format-based SQL with user values"],
  },
  unsafe_deserialization: {
    exploitationStory:
      "Untrusted serialized payloads are decoded into rich object graphs, enabling gadget chains or unsafe object behavior.",
    sourceArchetypes: [
      "upload/import payloads",
      "queue messages",
      "API request bodies",
      "cache/database serialized values",
    ],
    sinkArchetypes: [
      "unsafe deserialization APIs",
      "object mappers with polymorphic typing",
      "custom decoder hooks",
    ],
    sanitizers: ["safe loaders", "strict schema/type allowlists", "polymorphism disabled"],
    highPriority: [
      "restore/import endpoints",
      "message consumer deserializers",
      "cross-service decode boundaries",
    ],
    commonFalsePositives: [
      "safe loader usage",
      "schema-constrained decoding",
      "test serialization fixtures",
    ],
    oftenExploitable: [
      "unsafe load variants (Python/YAML/Java)",
      "deserialization of attacker-controlled blobs",
    ],
  },
  xss: {
    exploitationStory:
      "Attacker-controlled content is rendered in a browser context without escaping, enabling script execution under the victim session.",
    sourceArchetypes: [
      "HTTP params/body",
      "URL fragments",
      "database-stored user content",
      "WebSocket message payloads",
    ],
    sinkArchetypes: [
      "DOM innerHTML/outerHTML setters",
      "DOM write APIs",
      "React unsafe HTML props",
      "server-side unescaped template output",
      "response write with HTML content-type",
    ],
    sanitizers: [
      "context-aware HTML encoding",
      "Content-Security-Policy",
      "DOMPurify/sanitize-html",
      "auto-escaping template engines",
    ],
    highPriority: [
      "search result rendering",
      "user profile display",
      "comment/post rendering",
      "admin dashboards showing user content",
    ],
    commonFalsePositives: [
      "auto-escaping template output",
      "JSON API responses with proper content-type",
      "static HTML generation",
    ],
    oftenExploitable: [
      "raw user input assigned to DOM HTML properties",
      "server templates with unescaped interpolation",
      "reflected params in HTML response",
    ],
  },
  xxe: {
    exploitationStory:
      "Untrusted XML documents are parsed with external entity resolution enabled, allowing file disclosure, SSRF, or denial of service.",
    sourceArchetypes: [
      "XML file uploads",
      "SOAP request bodies",
      "SVG uploads",
      "XML import/export payloads",
      "SAML assertions",
    ],
    sinkArchetypes: [
      "XML parser APIs with default configuration",
      "XSLT processors",
      "XPath evaluators",
      "DOM/SAX parsers",
    ],
    sanitizers: [
      "disable external entities and DTDs in parser config",
      "schema validation before parsing",
      "JSON alternatives",
    ],
    highPriority: [
      "file upload handlers accepting XML/SVG",
      "SOAP endpoints",
      "SAML SSO integration",
      "document import features",
    ],
    commonFalsePositives: [
      "parsers with entities explicitly disabled",
      "JSON-only endpoints",
      "static XML configuration files",
    ],
    oftenExploitable: [
      "default XML parser configuration",
      "DTD processing enabled on user-supplied XML",
    ],
  },
  open_redirect: {
    exploitationStory:
      "User-controlled redirect targets allow attackers to redirect victims to malicious sites, enabling phishing and credential theft.",
    sourceArchetypes: [
      "return_url/redirect_uri params",
      "next/callback URL params",
      "Referer header values",
      "state parameters in OAuth flows",
    ],
    sinkArchetypes: [
      "HTTP redirect responses (301/302/307)",
      "meta refresh tags",
      "window.location assignments",
      "Location header construction",
    ],
    sanitizers: [
      "allowlisted redirect domains",
      "relative-path-only redirects",
      "strict URL parsing with host validation",
    ],
    highPriority: [
      "login/logout redirect flows",
      "OAuth callback handlers",
      "SSO return URL handling",
      "email link click tracking",
    ],
    commonFalsePositives: [
      "hardcoded redirect targets",
      "relative path redirects",
      "strict domain allowlist validation",
    ],
    oftenExploitable: [
      "raw query param used as redirect target",
      "protocol-relative URLs bypassing host checks",
    ],
  },
  header_injection: {
    exploitationStory:
      "Attacker-controlled data is injected into HTTP response headers, enabling response splitting, cache poisoning, or session fixation.",
    sourceArchetypes: [
      "HTTP params/body",
      "cookie values",
      "URL path segments",
      "user profile fields",
    ],
    sinkArchetypes: [
      "Set-Cookie header construction",
      "Location header construction",
      "custom response header APIs",
      "Content-Disposition filename",
    ],
    sanitizers: [
      "CRLF stripping/rejection",
      "header value encoding",
      "framework-provided header APIs that auto-encode",
    ],
    highPriority: [
      "cookie-setting endpoints",
      "download handlers with filename headers",
      "redirect construction",
      "CORS header builders",
    ],
    commonFalsePositives: [
      "framework-managed headers with auto-encoding",
      "constant header values",
      "test response helpers",
    ],
    oftenExploitable: [
      "raw string concatenation into headers",
      "CRLF injection in Set-Cookie values",
    ],
  },
  log_injection: {
    exploitationStory:
      "Untrusted input is written to log entries without sanitization, enabling log forging, log-based injection attacks, or SIEM evasion.",
    sourceArchetypes: [
      "HTTP params/body",
      "user agent strings",
      "authentication tokens",
      "error messages from user input",
    ],
    sinkArchetypes: [
      "structured/unstructured log APIs",
      "audit trail writers",
      "error reporting with user context",
      "console output in production",
    ],
    sanitizers: [
      "structured logging with parameterized fields",
      "newline/control character stripping",
      "log encoding libraries",
    ],
    highPriority: [
      "authentication logging",
      "audit trail endpoints",
      "error handlers logging request data",
      "admin activity logging",
    ],
    commonFalsePositives: [
      "structured logging frameworks with auto-encoding",
      "internal-only debug logs",
      "test logging",
    ],
    oftenExploitable: [
      "user input interpolated into log format strings",
      "newline injection enabling log forging",
    ],
  },
  ldap_injection: {
    exploitationStory:
      "User-controlled input is interpolated into LDAP queries, enabling authentication bypass, data exfiltration, or directory modification.",
    sourceArchetypes: [
      "login username/password fields",
      "directory search params",
      "group membership queries",
      "user lookup fields",
    ],
    sinkArchetypes: [
      "LDAP search filter construction",
      "LDAP bind operations",
      "directory query APIs",
      "Active Directory query builders",
    ],
    sanitizers: [
      "LDAP filter escaping (RFC 4515)",
      "parameterized LDAP queries",
      "input validation against strict patterns",
    ],
    highPriority: [
      "LDAP authentication handlers",
      "directory search endpoints",
      "user/group management APIs",
      "SSO integration code",
    ],
    commonFalsePositives: [
      "hardcoded LDAP filters",
      "properly escaped filter construction",
      "test LDAP fixtures",
    ],
    oftenExploitable: [
      "string-concatenated LDAP filters with user input",
      "unescaped DN construction",
    ],
  },
  ssti: {
    exploitationStory:
      "User-controlled content is embedded into server-side templates and rendered, enabling arbitrary code execution on the server.",
    sourceArchetypes: [
      "template content fields",
      "email template customization",
      "CMS page content",
      "notification message templates",
    ],
    sinkArchetypes: [
      "server-side template render APIs",
      "template-from-string constructors",
      "dynamic template compilation",
      "eval-capable template engines",
    ],
    sanitizers: [
      "sandboxed template engines",
      "logic-less templates (Mustache)",
      "template content allowlists",
      "pre-compiled templates only",
    ],
    highPriority: [
      "CMS/page builder features",
      "email template editors",
      "notification template systems",
      "user-customizable report generators",
    ],
    commonFalsePositives: [
      "pre-compiled static templates",
      "logic-less template engines",
      "admin-only template editing with trust boundary",
    ],
    oftenExploitable: [
      "user input rendered as template source",
      "template-from-string with Jinja2/Twig/Freemarker",
    ],
  },
};

export async function buildTiPriorArtifacts(options: BuildTiPriorOptions): Promise<{
  document: TiPriorDocument;
  markdown: string;
}> {
  const { passes, timeoutMs } = options;
  const generatedAt = new Date().toISOString();
  const targetCwes = collectCwes(passes);
  const errors: string[] = [];

  let kevVulns: KevVulnerability[] = [];
  try {
    const kev = await fetchKev(timeoutMs);
    kevVulns = kev.vulnerabilities ?? [];
  } catch (error) {
    errors.push(`CISA KEV fetch failed: ${toErrorMessage(error)}`);
  }

  const nvdByCwe = new Map<string, NvdVulnerability[]>();
  for (const cwe of targetCwes) {
    try {
      const nvd = await fetchNvd(cwe, timeoutMs);
      nvdByCwe.set(cwe, nvd.vulnerabilities ?? []);
    } catch (error) {
      errors.push(`NVD fetch failed for ${cwe}: ${toErrorMessage(error)}`);
    }
  }

  const cwes: TiPriorCwe[] = targetCwes.map((cwe) => {
    const pass = passes.find((item) => item.cwes.some((code) => normalizeCwe(code) === cwe));
    const template = pass ? FOCUS_TEMPLATES[pass.passKey] : undefined;
    const focus = pass?.focus ?? "Unknown";
    const references = [
      ...extractKevReferences(cwe, kevVulns),
      ...extractNvdReferences(cwe, nvdByCwe.get(cwe) ?? []),
    ];
    const tiWeight: TiPriorCwe["tiWeight"] = references.some((ref) => ref.source === "cisa-kev")
      ? "HIGH"
      : references.length > 0
        ? "MEDIUM"
        : "LOW";

    return {
      cwe,
      focus,
      exploitationStory:
        template?.exploitationStory ??
        "Model attacker-controlled input paths and execution-impacting sinks conservatively.",
      sourceArchetypes: template?.sourceArchetypes ?? [],
      sinkArchetypes: template?.sinkArchetypes ?? [],
      sanitizers: template?.sanitizers ?? [],
      references,
      tiWeight,
      highPriority: template?.highPriority ?? [],
      commonFalsePositives: template?.commonFalsePositives ?? [],
      oftenExploitable: template?.oftenExploitable ?? [],
    };
  });

  const document: TiPriorDocument = {
    version: "1.0.0",
    generatedAt,
    mode: "live-required",
    degraded: errors.length > 0,
    errors,
    cwes,
  };

  return {
    document,
    markdown: renderTiPriorMarkdown(document),
  };
}

function collectCwes(passes: TaintAnalysisPassDefinition[]): string[] {
  const out = new Set<string>();
  for (const pass of passes) {
    for (const cwe of pass.cwes) {
      out.add(normalizeCwe(cwe));
    }
  }
  return [...out];
}

function normalizeCwe(value: string): string {
  const digits = value.replace(/[^0-9]/g, "");
  const numeric = Number.parseInt(digits, 10);
  if (!Number.isFinite(numeric)) {
    return "CWE-000";
  }
  return `CWE-${numeric}`;
}

async function fetchKev(timeoutMs: number): Promise<KevResponse> {
  return fetchJson<KevResponse>(KEV_URL, timeoutMs);
}

async function fetchNvd(cwe: string, timeoutMs: number): Promise<NvdResponse> {
  const url = `${NVD_URL_BASE}?cweId=${encodeURIComponent(cwe)}&resultsPerPage=20`;
  return fetchJson<NvdResponse>(url, timeoutMs);
}

async function fetchJson<T>(url: string, timeoutMs: number): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        accept: "application/json",
        "user-agent": "kuzushi-taint-analysis-ti/0.1",
      },
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }
    return (await response.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

function extractKevReferences(cwe: string, vulnerabilities: KevVulnerability[]): TiReference[] {
  const out: TiReference[] = [];
  for (const vuln of vulnerabilities) {
    const cweSet = normalizeKevCwes(vuln.cwes);
    if (!cweSet.has(cwe)) {
      continue;
    }

    const cve = sanitize(vuln.cveID);
    if (!cve) {
      continue;
    }
    const titleBase =
      sanitize(vuln.shortDescription) ||
      `${sanitize(vuln.vendorProject)} ${sanitize(vuln.product)}`.trim();
    const title = titleBase || `${cve} listed in CISA KEV`;
    out.push({
      source: "cisa-kev",
      id: cve,
      url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(cve)}`,
      title,
    });
  }
  return uniqueReferences(out);
}

function extractNvdReferences(cwe: string, vulnerabilities: NvdVulnerability[]): TiReference[] {
  const out: TiReference[] = [];
  for (const item of vulnerabilities) {
    const cve = item.cve;
    if (!cve?.id) {
      continue;
    }

    if (!nvdMatchesCwe(cwe, cve)) {
      continue;
    }

    const description = pickNvdDescription(cve);
    out.push({
      source: "nvd",
      id: cve.id,
      url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`,
      title: description || `${cve.id} (NVD)`,
    });
  }
  return uniqueReferences(out);
}

function normalizeKevCwes(value: string | string[] | undefined): Set<string> {
  const out = new Set<string>();
  if (typeof value === "string") {
    for (const token of value.split(/[,\s]+/)) {
      const normalized = normalizeCwe(token);
      if (normalized !== "CWE-000") {
        out.add(normalized);
      }
    }
    return out;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const normalized = normalizeCwe(String(item));
      if (normalized !== "CWE-000") {
        out.add(normalized);
      }
    }
  }
  return out;
}

function nvdMatchesCwe(target: string, cve: NvdCve): boolean {
  const targetLower = target.toLowerCase();
  for (const weakness of cve.weaknesses ?? []) {
    for (const desc of weakness.description ?? []) {
      const value = String(desc.value ?? "").toLowerCase();
      if (!value) {
        continue;
      }
      if (value.includes(targetLower)) {
        return true;
      }
    }
  }
  return false;
}

function pickNvdDescription(cve: NvdCve): string {
  const english = cve.descriptions?.find((desc) => desc.lang === "en")?.value;
  if (english) {
    return trimTo(english, 160);
  }
  const any = cve.descriptions?.[0]?.value;
  return any ? trimTo(any, 160) : "";
}

function trimTo(value: string, maxLength: number): string {
  const trimmed = value.trim();
  if (trimmed.length <= maxLength) {
    return trimmed;
  }
  return `${trimmed.slice(0, maxLength - 1)}…`;
}

function uniqueReferences(refs: TiReference[]): TiReference[] {
  const map = new Map<string, TiReference>();
  for (const ref of refs) {
    map.set(`${ref.source}:${ref.id}`, ref);
  }
  return [...map.values()];
}

function sanitize(value: unknown): string {
  if (typeof value !== "string") {
    return "";
  }
  return value.trim();
}

function renderTiPriorMarkdown(doc: TiPriorDocument): string {
  const lines: string[] = [
    "# TI Prior",
    "",
    `- Generated at: ${doc.generatedAt}`,
    `- Mode: ${doc.mode}`,
    `- Degraded: ${doc.degraded ? "yes" : "no"}`,
    "",
  ];

  if (doc.errors.length > 0) {
    lines.push("## Fetch Issues");
    for (const error of doc.errors) {
      lines.push(`- ${error}`);
    }
    lines.push("");
  }

  for (const entry of doc.cwes) {
    lines.push(`## ${entry.cwe} (${entry.focus})`);
    lines.push(`- TI Weight: ${entry.tiWeight}`);
    lines.push(`- Exploitation story: ${entry.exploitationStory}`);
    lines.push("- Source archetypes:");
    for (const item of entry.sourceArchetypes) {
      lines.push(`  - ${item}`);
    }
    lines.push("- Sink archetypes:");
    for (const item of entry.sinkArchetypes) {
      lines.push(`  - ${item}`);
    }
    lines.push("- Sanitizers:");
    for (const item of entry.sanitizers) {
      lines.push(`  - ${item}`);
    }
    lines.push("- High priority:");
    for (const item of entry.highPriority) {
      lines.push(`  - ${item}`);
    }
    lines.push("- Common false positives:");
    for (const item of entry.commonFalsePositives) {
      lines.push(`  - ${item}`);
    }
    lines.push("- Often exploitable:");
    for (const item of entry.oftenExploitable) {
      lines.push(`  - ${item}`);
    }
    lines.push("- References:");
    if (entry.references.length === 0) {
      lines.push("  - none");
    } else {
      for (const ref of entry.references) {
        lines.push(`  - [${ref.id}](${ref.url}) (${ref.source}) — ${ref.title}`);
      }
    }
    lines.push("");
  }

  return lines.join("\n");
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
