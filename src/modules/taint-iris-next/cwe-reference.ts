interface ThreatModelDocument {
  threats?: Array<{
    title?: string;
    description?: string;
    attackVector?: string;
    relatedCwe?: string[];
    missingMitigations?: string[];
    preconditions?: string[];
    cwe?: string | string[];
    cwes?: string[];
    [key: string]: unknown;
  }>;
  [key: string]: unknown;
}

interface RepoContext {
  languages?: string[];
  frameworks?: string[];
  authPatterns?: string[];
  sanitizationLibs?: string[];
  ormOrDb?: string[];
  entryPoints?: string[];
  [key: string]: unknown;
}

export interface TaintIrisNextBackendHints {
  codeql?: string;
  semgrep?: string;
  joern?: string;
  language?: string;
}

export interface TaintIrisNextCweCatalogEntry {
  cwe: string;
  name: string;
  taintClass: string;
  languages: readonly string[];
  sourceSignals: readonly string[];
  sinkSignals: readonly string[];
  sanitizerSignals: readonly string[];
  structuralQueries: readonly string[];
  backendHints?: TaintIrisNextBackendHints;
}

export interface RankedTaintIrisNextCweCatalogEntry extends TaintIrisNextCweCatalogEntry {
  score: number;
  reasons: readonly string[];
}

export interface TaintIrisNextStructuralQuery {
  id: string;
  cwe: string;
  taintClass: string;
  role: "source" | "sink" | "sanitizer" | "structural";
  pattern: string;
  languages: readonly string[];
}

export interface TaintIrisNextAgentCweSelection {
  cwe: string;
  reason?: string;
  signalCitations?: readonly string[];
  catalogSignals?: readonly string[];
  customCweRationale?: string;
}

export interface TaintIrisNextSelectionValidation {
  valid: boolean;
  accepted: Array<TaintIrisNextAgentCweSelection & { cwe: string; knownCatalogCwe: boolean }>;
  rejected: Array<{ cwe: string; reason: string }>;
}

const ANY = ["any"] as const;
const WEB = ["javascript", "typescript", "python", "ruby", "php", "java", "go", "csharp"] as const;
const NATIVE = ["c", "cpp", "go", "rust"] as const;

function e(entry: TaintIrisNextCweCatalogEntry): TaintIrisNextCweCatalogEntry {
  return entry;
}

export const TAINT_IRIS_NEXT_CWE_CATALOG = [
  e({
    cwe: "CWE-22",
    name: "Path Traversal",
    taintClass: "path-traversal",
    languages: ANY,
    sourceSignals: ["request path", "query filename", "archive entry name", "upload filename"],
    sinkSignals: ["open", "readFile", "writeFile", "File.open", "PathBuf::push", "send_file"],
    sanitizerSignals: ["basename", "realpath", "canonicalize", "safe_join", "filepath.Clean"],
    structuralQueries: ["../", "path.join", "readFile", "File.open", "PathBuf", "send_file"],
    backendHints: {
      codeql: "Model remote request fields as sources and filesystem APIs as path sinks.",
      semgrep: "Search user-controlled path concatenation before filesystem calls.",
    },
  }),
  e({
    cwe: "CWE-73",
    name: "External Control of File Name or Path",
    taintClass: "externally-controlled-path",
    languages: ANY,
    sourceSignals: ["config path", "request path", "environment variable", "CLI argument"],
    sinkSignals: ["open", "create", "rename", "copy", "unlink", "readFile", "writeFile"],
    sanitizerSignals: ["allowlist path", "canonicalize", "chroot", "safe_join"],
    structuralQueries: ["process.argv", "ENV[", "os.environ", "std::env::args", "rename("],
    backendHints: {
      codeql: "Prefer path-injection queries with environment and CLI argument sources.",
    },
  }),
  e({
    cwe: "CWE-77",
    name: "Command Injection",
    taintClass: "command-injection",
    languages: ANY,
    sourceSignals: ["request parameter", "CLI argument", "environment variable", "message payload"],
    sinkSignals: ["exec", "spawn", "system", "popen", "Command::new", "subprocess", "shell"],
    sanitizerSignals: ["argument array", "shell escape", "allowlist command", "quote"],
    structuralQueries: ["exec(", "spawn(", "system(", "popen(", "Command::new", "subprocess"],
    backendHints: {
      codeql: "Generate command injection queries for process execution sinks.",
      semgrep: "Match shell=True, exec string interpolation, and system command concatenation.",
    },
  }),
  e({
    cwe: "CWE-78",
    name: "OS Command Injection",
    taintClass: "os-command-injection",
    languages: ANY,
    sourceSignals: ["request parameter", "CLI argument", "job payload", "webhook body"],
    sinkSignals: [
      "child_process.exec",
      "os.system",
      "Runtime.exec",
      "Command::new",
      "Open3",
      "subprocess",
      "Popen",
      "shell=True",
    ],
    sanitizerSignals: ["execFile", "argument vector", "allowlist", "shellwords"],
    structuralQueries: [
      "child_process",
      "Runtime.getRuntime().exec",
      "Open3",
      "Shellwords",
      "subprocess",
      "Popen",
      "shell=True",
    ],
    backendHints: {
      codeql: "Treat shell command string arguments as sinks and arg-vector APIs as lower risk.",
    },
  }),
  e({
    cwe: "CWE-79",
    name: "Cross-Site Scripting",
    taintClass: "xss",
    languages: WEB,
    sourceSignals: ["request body", "query parameter", "stored profile field", "markdown input"],
    sinkSignals: ["render", "send", "html", "innerHTML", "template", "raw"],
    sanitizerSignals: ["escapeHtml", "sanitize", "DOMPurify", "html_safe", "SafeBuffer"],
    structuralQueries: ["innerHTML", "dangerouslySetInnerHTML", "html_safe", "render", "res.send"],
    backendHints: {
      semgrep: "Search unsanitized request data reaching HTML or template output.",
    },
  }),
  e({
    cwe: "CWE-89",
    name: "SQL Injection",
    taintClass: "sql-injection",
    languages: ANY,
    sourceSignals: ["request body", "query parameter", "route parameter", "job payload"],
    sinkSignals: ["query", "execute", "exec", "raw", "where", "find_by_sql", "Sequelize.literal"],
    sanitizerSignals: ["parameterized query", "prepared statement", "bind parameter", "escape"],
    structuralQueries: [
      "SELECT",
      "WHERE",
      "query(",
      "execute(",
      "find_by_sql",
      "Sequelize.literal",
    ],
    backendHints: {
      codeql: "Generate remote-flow-to-sql-sink taint configs with ORM raw query methods.",
      semgrep: "Match SQL string interpolation and raw query builder calls.",
    },
  }),
  e({
    cwe: "CWE-90",
    name: "LDAP Injection",
    taintClass: "ldap-injection",
    languages: WEB,
    sourceSignals: ["login field", "search query", "directory lookup parameter"],
    sinkSignals: ["ldap search", "LDAP filter", "DirContext.search", "Net::LDAP"],
    sanitizerSignals: ["escapeLDAP", "ldap_escape", "filter encoder"],
    structuralQueries: ["ldap", "DirContext.search", "Net::LDAP", "LDAP::Filter"],
    backendHints: { codeql: "Model LDAP filter construction as string-building sinks." },
  }),
  e({
    cwe: "CWE-94",
    name: "Code Injection",
    taintClass: "code-injection",
    languages: ["javascript", "typescript", "python", "ruby", "php", "java"],
    sourceSignals: ["request parameter", "template expression", "workflow expression"],
    sinkSignals: ["eval", "Function", "exec", "compile", "class_eval", "instance_eval"],
    sanitizerSignals: ["allowlist expression", "sandbox", "parser restriction"],
    structuralQueries: ["eval(", "Function(", "compile(", "class_eval", "instance_eval"],
    backendHints: { codeql: "Track untrusted strings into dynamic code evaluation APIs." },
  }),
  e({
    cwe: "CWE-95",
    name: "Eval Injection",
    taintClass: "eval-injection",
    languages: ["javascript", "typescript", "python", "ruby", "php"],
    sourceSignals: ["request parameter", "stored expression", "automation script"],
    sinkSignals: ["eval", "Function", "exec", "instance_eval"],
    sanitizerSignals: ["allowlist", "AST validation", "sandbox"],
    structuralQueries: ["eval(", "new Function", "exec(", "instance_eval"],
    backendHints: { semgrep: "Match eval-like APIs with non-literal arguments." },
  }),
  e({
    cwe: "CWE-113",
    name: "HTTP Header Injection",
    taintClass: "header-injection",
    languages: WEB,
    sourceSignals: ["request parameter", "redirect URL", "filename", "header value"],
    sinkSignals: ["setHeader", "header", "headers[", "response.set", "redirect"],
    sanitizerSignals: ["strip CRLF", "header allowlist", "encodeURIComponent"],
    structuralQueries: ["setHeader", "headers[", "response.headers", "redirect("],
    backendHints: { semgrep: "Search CRLF-bearing input reaching response header setters." },
  }),
  e({
    cwe: "CWE-117",
    name: "Log Injection",
    taintClass: "log-injection",
    languages: ANY,
    sourceSignals: ["request parameter", "username", "header", "job payload"],
    sinkSignals: ["logger", "log.info", "puts", "println", "tracing::", "slog"],
    sanitizerSignals: ["strip CRLF", "structured logging", "JSON encoding"],
    structuralQueries: ["logger.", "log.info", "println", "tracing::", "Rails.logger"],
    backendHints: { semgrep: "Match untrusted data interpolated into line-oriented logs." },
  }),
  e({
    cwe: "CWE-190",
    name: "Integer Overflow",
    taintClass: "integer-overflow",
    languages: NATIVE,
    sourceSignals: ["length field", "size parameter", "count", "offset", "capacity"],
    sinkSignals: ["allocation", "copy", "slice", "index", "resize"],
    sanitizerSignals: ["checked_add", "saturating", "bounds check", "try_from"],
    structuralQueries: ["checked_add", "saturating_", "malloc", "resize", "capacity"],
    backendHints: { joern: "Trace tainted size operands into allocation or copy length sinks." },
  }),
  e({
    cwe: "CWE-200",
    name: "Exposure of Sensitive Information",
    taintClass: "info-exposure",
    languages: ANY,
    sourceSignals: ["secret", "token", "credential", "private data", "PII"],
    sinkSignals: ["response body", "log", "error message", "GraphQL field", "export"],
    sanitizerSignals: ["redact", "mask", "omit", "authorization check"],
    structuralQueries: ["password", "token", "secret", "redact", "mask"],
    backendHints: {
      semgrep: "Search sensitive fields returned or logged without authorization gates.",
    },
  }),
  e({
    cwe: "CWE-287",
    name: "Improper Authentication",
    taintClass: "authentication-bypass",
    languages: WEB,
    sourceSignals: ["login request", "session cookie", "API key", "JWT"],
    sinkSignals: ["session creation", "current_user", "authenticate", "signIn"],
    sanitizerSignals: ["password verify", "signature verify", "constant-time compare"],
    structuralQueries: ["authenticate", "current_user", "jwt", "session", "password"],
    backendHints: { language: "Prefer framework-specific auth guard inspection." },
  }),
  e({
    cwe: "CWE-326",
    name: "Inadequate Encryption Strength",
    taintClass: "weak-crypto",
    languages: ANY,
    sourceSignals: ["crypto configuration", "cipher name", "key size"],
    sinkSignals: ["createCipher", "Cipher.getInstance", "OpenSSL::Cipher", "ring::"],
    sanitizerSignals: ["AEAD", "AES-256-GCM", "minimum key length"],
    structuralQueries: ["DES", "RC4", "ECB", "md5", "sha1"],
    backendHints: { semgrep: "Match deprecated algorithms and small key sizes." },
  }),
  e({
    cwe: "CWE-327",
    name: "Broken or Risky Cryptographic Algorithm",
    taintClass: "weak-crypto",
    languages: ANY,
    sourceSignals: ["algorithm name", "hash choice", "cipher suite"],
    sinkSignals: ["crypto.createHash", "MessageDigest", "OpenSSL::Digest", "hashlib"],
    sanitizerSignals: ["approved algorithm allowlist", "modern KDF", "AEAD"],
    structuralQueries: ["md5", "sha1", "createHash", "MessageDigest", "OpenSSL::Digest"],
    backendHints: { semgrep: "Match risky algorithm literals in crypto constructors." },
  }),
  e({
    cwe: "CWE-346",
    name: "Origin Validation Error",
    taintClass: "origin-validation",
    languages: WEB,
    sourceSignals: ["Origin header", "Host header", "webhook source", "callback URL"],
    sinkSignals: ["CORS allow", "redirect", "webhook trust", "cross-service action"],
    sanitizerSignals: ["origin allowlist", "signature verification", "host allowlist"],
    structuralQueries: ["Origin", "Access-Control-Allow-Origin", "host", "webhook"],
    backendHints: { language: "Inspect framework CORS and webhook validation middleware." },
  }),
  e({
    cwe: "CWE-352",
    name: "Cross-Site Request Forgery",
    taintClass: "csrf",
    languages: WEB,
    sourceSignals: ["browser request", "cookie-authenticated route", "form post"],
    sinkSignals: ["state change", "delete", "transfer", "admin action"],
    sanitizerSignals: ["CSRF token", "SameSite", "origin check"],
    structuralQueries: ["csrf", "SameSite", "protect_from_forgery", "csurf"],
    backendHints: {
      semgrep: "Find state-changing routes missing CSRF middleware or origin checks.",
    },
  }),
  e({
    cwe: "CWE-362",
    name: "Race Condition",
    taintClass: "race-condition",
    languages: ANY,
    sourceSignals: ["concurrent request", "job retry", "parallel worker", "shared key"],
    sinkSignals: ["balance update", "state transition", "file write", "cache mutation"],
    sanitizerSignals: ["lock", "transaction", "compare-and-swap", "unique constraint"],
    structuralQueries: ["transaction", "lock", "mutex", "SELECT", "UPDATE"],
    backendHints: { language: "Reason over read-check-write sequences and missing atomicity." },
  }),
  e({
    cwe: "CWE-367",
    name: "Time-of-check Time-of-use Race Condition",
    taintClass: "toctou",
    languages: ANY,
    sourceSignals: ["filename", "resource id", "authorization target"],
    sinkSignals: ["exists then open", "check then write", "stat then use"],
    sanitizerSignals: ["atomic open", "transaction", "lock", "single SQL statement"],
    structuralQueries: ["exists", "stat", "access", "open", "transaction"],
    backendHints: { joern: "Search check/use pairs over the same tainted resource." },
  }),
  e({
    cwe: "CWE-400",
    name: "Uncontrolled Resource Consumption",
    taintClass: "resource-exhaustion",
    languages: ANY,
    sourceSignals: ["limit parameter", "page size", "regex input", "upload size", "loop count"],
    sinkSignals: ["allocation", "loop", "regex", "query all", "decompression"],
    sanitizerSignals: ["limit cap", "timeout", "quota", "rate limit"],
    structuralQueries: ["limit", "timeout", "rateLimit", "while", "regex"],
    backendHints: {
      semgrep: "Search attacker-controlled size or regex reaching expensive operations.",
    },
  }),
  e({
    cwe: "CWE-434",
    name: "Unrestricted Upload of Dangerous File Type",
    taintClass: "file-upload",
    languages: WEB,
    sourceSignals: ["multipart upload", "attachment", "filename", "content type"],
    sinkSignals: ["save upload", "write file", "public path", "extract archive"],
    sanitizerSignals: ["extension allowlist", "content sniff", "virus scan", "randomized name"],
    structuralQueries: ["multipart", "upload", "multer", "ActiveStorage", "content_type"],
    backendHints: { semgrep: "Match upload handlers that save user filenames into served paths." },
  }),
  e({
    cwe: "CWE-502",
    name: "Unsafe Deserialization",
    taintClass: "deserialization",
    languages: ["javascript", "typescript", "python", "ruby", "php", "java", "csharp"],
    sourceSignals: ["request body", "cookie", "message payload", "cache value"],
    sinkSignals: ["deserialize", "pickle.loads", "Marshal.load", "ObjectInputStream", "YAML.load"],
    sanitizerSignals: ["safe_load", "schema validation", "class allowlist", "signed payload"],
    structuralQueries: [
      "deserialize",
      "pickle.loads",
      "Marshal.load",
      "YAML.load",
      "ObjectInputStream",
    ],
    backendHints: { codeql: "Track remote byte/string payloads into unsafe deserialize APIs." },
  }),
  e({
    cwe: "CWE-601",
    name: "Open Redirect",
    taintClass: "open-redirect",
    languages: WEB,
    sourceSignals: ["next URL", "return_to", "redirect parameter", "callback URL"],
    sinkSignals: ["redirect", "RedirectResponse", "sendRedirect", "res.redirect"],
    sanitizerSignals: ["same-origin check", "path-only redirect", "host allowlist"],
    structuralQueries: ["redirect(", "return_to", "next=", "sendRedirect", "RedirectResponse"],
    backendHints: { semgrep: "Match request parameters used directly as redirect destinations." },
  }),
  e({
    cwe: "CWE-611",
    name: "XML External Entity",
    taintClass: "xxe",
    languages: ["java", "python", "ruby", "php", "go", "csharp"],
    sourceSignals: ["XML request body", "uploaded XML", "SOAP payload"],
    sinkSignals: ["XML parser", "DocumentBuilder", "SAXParser", "Nokogiri", "lxml"],
    sanitizerSignals: ["disable external entities", "secure processing", "no network"],
    structuralQueries: [
      "DocumentBuilderFactory",
      "SAXParser",
      "Nokogiri::XML",
      "lxml",
      "xml.NewDecoder",
    ],
    backendHints: { codeql: "Find XML parsers without XXE-hardening flags." },
  }),
  e({
    cwe: "CWE-639",
    name: "Authorization Bypass Through User-Controlled Key",
    taintClass: "idor",
    languages: WEB,
    sourceSignals: ["route id", "account id", "organization id", "object key"],
    sinkSignals: ["find by id", "load record", "update owner resource"],
    sanitizerSignals: ["owner check", "tenant scope", "policy authorize"],
    structuralQueries: ["params[:id]", "req.params", "authorize", "policy", "tenant"],
    backendHints: {
      language: "Inspect route parameter flows into object loads without policy checks.",
    },
  }),
  e({
    cwe: "CWE-776",
    name: "XML Entity Expansion",
    taintClass: "xml-entity-expansion",
    languages: ["java", "python", "ruby", "php", "go", "csharp"],
    sourceSignals: ["XML request body", "uploaded XML", "SOAP payload"],
    sinkSignals: ["XML parser", "DTD", "entity resolver"],
    sanitizerSignals: ["disable DTD", "entity expansion limit", "secure processing"],
    structuralQueries: ["DOCTYPE", "setFeature", "EntityResolver", "LoadOptions"],
    backendHints: { semgrep: "Find XML parsers that allow DTD/entity expansion." },
  }),
  e({
    cwe: "CWE-798",
    name: "Hard-coded Credentials",
    taintClass: "hardcoded-credentials",
    languages: ANY,
    sourceSignals: ["literal secret", "default password", "API token", "private key"],
    sinkSignals: ["auth header", "database password", "cloud credential", "signing key"],
    sanitizerSignals: ["secret manager", "environment lookup", "vault reference"],
    structuralQueries: ["password", "api_key", "secret", "BEGIN PRIVATE KEY", "Authorization"],
    backendHints: { semgrep: "Search credential-like literals assigned to auth configuration." },
  }),
  e({
    cwe: "CWE-829",
    name: "Inclusion of Functionality from Untrusted Control Sphere",
    taintClass: "supply-chain",
    languages: ANY,
    sourceSignals: ["dependency name", "plugin URL", "script hook", "package registry"],
    sinkSignals: ["install script", "dynamic import", "plugin load", "remote code fetch"],
    sanitizerSignals: ["lockfile integrity", "signature verification", "pinned source"],
    structuralQueries: ["postinstall", "dynamic import", "require(", "plugin", "integrity"],
    backendHints: { semgrep: "Search dependency/plugin autoload paths controlled by repo config." },
  }),
  e({
    cwe: "CWE-862",
    name: "Missing Authorization",
    taintClass: "missing-authorization",
    languages: WEB,
    sourceSignals: ["route", "resolver", "controller action", "RPC method"],
    sinkSignals: ["sensitive object", "admin action", "tenant data", "mutation"],
    sanitizerSignals: ["authorize", "policy", "permission check", "guard"],
    structuralQueries: ["authorize", "policy", "permission", "before_action", "guard"],
    backendHints: {
      language: "Compare route/resolver criticality to nearby authorization guards.",
    },
  }),
  e({
    cwe: "CWE-863",
    name: "Incorrect Authorization",
    taintClass: "incorrect-authorization",
    languages: WEB,
    sourceSignals: ["route id", "role", "tenant id", "feature flag"],
    sinkSignals: ["privileged action", "record mutation", "admin API"],
    sanitizerSignals: ["role check", "tenant check", "object-level policy"],
    structuralQueries: ["role", "tenant", "authorize", "admin", "policy"],
    backendHints: {
      language: "Look for partial checks that miss object ownership or tenant scope.",
    },
  }),
  e({
    cwe: "CWE-915",
    name: "Mass Assignment",
    taintClass: "mass-assignment",
    languages: WEB,
    sourceSignals: ["request body", "JSON payload", "form params"],
    sinkSignals: ["update attributes", "assign", "create", "merge into model"],
    sanitizerSignals: ["strong parameters", "permit", "schema pick", "DTO allowlist"],
    structuralQueries: ["update(", "assign_attributes", "permit(", "Object.assign", "merge("],
    backendHints: { semgrep: "Find bulk assignment of request bodies into domain models." },
  }),
  e({
    cwe: "CWE-918",
    name: "Server-Side Request Forgery",
    taintClass: "ssrf",
    languages: ANY,
    sourceSignals: ["URL parameter", "webhook URL", "callback URL", "import URL"],
    sinkSignals: ["fetch", "request", "http.Get", "Net::HTTP", "Faraday", "reqwest"],
    sanitizerSignals: ["URL allowlist", "IP blocklist", "DNS pinning", "no private network"],
    structuralQueries: ["fetch(", "http.Get", "Net::HTTP", "Faraday", "reqwest", "axios"],
    backendHints: {
      codeql: "Track remote URL input into outbound HTTP client sinks.",
      semgrep: "Match request parameter URLs passed to outbound HTTP clients.",
    },
  }),
  e({
    cwe: "CWE-943",
    name: "NoSQL Injection",
    taintClass: "nosql-injection",
    languages: ["javascript", "typescript", "python", "ruby", "java", "csharp"],
    sourceSignals: ["JSON body", "query object", "filter parameter"],
    sinkSignals: ["find", "findOne", "aggregate", "$where", "where"],
    sanitizerSignals: ["schema validation", "operator allowlist", "type coercion"],
    structuralQueries: ["$where", "findOne", "aggregate", "Mongo", "mongoose"],
    backendHints: { semgrep: "Search request JSON objects passed directly into NoSQL filters." },
  }),
  e({
    cwe: "CWE-1321",
    name: "Prototype Pollution",
    taintClass: "prototype-pollution",
    languages: ["javascript", "typescript"],
    sourceSignals: ["JSON body", "query object", "merge source", "path key"],
    sinkSignals: ["merge", "assign", "set", "defaultsDeep", "lodash"],
    sanitizerSignals: ["key denylist", "plain object clone", "schema validation"],
    structuralQueries: ["__proto__", "constructor", "prototype", "merge", "defaultsDeep"],
    backendHints: { semgrep: "Match recursive merge/set helpers reachable from request bodies." },
  }),
  e({
    cwe: "CWE-1333",
    name: "Inefficient Regular Expression Complexity",
    taintClass: "regex-injection",
    languages: ["javascript", "typescript", "python", "ruby", "php", "java"],
    sourceSignals: ["search query", "pattern parameter", "validation regex"],
    sinkSignals: ["RegExp", "re.compile", "Pattern.compile", "match", "scan"],
    sanitizerSignals: ["literal escape", "timeout", "safe-regex", "length cap"],
    structuralQueries: ["RegExp", "re.compile", "Pattern.compile", "match(", "scan("],
    backendHints: {
      semgrep: "Search user-controlled regex construction and catastrophic patterns.",
    },
  }),
  e({
    cwe: "CWE-1336",
    name: "Server-Side Template Injection",
    taintClass: "ssti",
    languages: ["javascript", "typescript", "python", "ruby", "php", "java"],
    sourceSignals: ["template parameter", "CMS content", "email template", "workflow template"],
    sinkSignals: ["render_template_string", "Template.new", "Handlebars.compile", "ERB.new"],
    sanitizerSignals: ["template allowlist", "sandbox", "escaping only output"],
    structuralQueries: ["render_template_string", "Template.new", "Handlebars.compile", "ERB.new"],
    backendHints: { codeql: "Track untrusted template strings into dynamic template compilation." },
  }),
] as const satisfies readonly TaintIrisNextCweCatalogEntry[];

export const TAINT_IRIS_NEXT_CWE_CATALOG_BY_ID: ReadonlyMap<string, TaintIrisNextCweCatalogEntry> =
  new Map(TAINT_IRIS_NEXT_CWE_CATALOG.map((entry) => [entry.cwe, entry]));

export function normalizeCweId(value: string): string {
  const match = value.trim().match(/^(?:CWE[-_\s]*)?0*(\d+)$/iu);
  if (!match) return value.trim().toUpperCase();
  return `CWE-${Number.parseInt(match[1]!, 10)}`;
}

export function filterCatalogForContext(
  context: RepoContext | undefined,
  threatModel: ThreatModelDocument | undefined,
  languages: readonly string[] = [],
): TaintIrisNextCweCatalogEntry[] {
  const languageSet = collectLanguageSet(context, languages);
  const threatCwes = collectThreatCwes(threatModel);
  const hasContext = languageSet.size > 0 || threatCwes.size > 0 || !!context || !!threatModel;

  if (!hasContext) return [...TAINT_IRIS_NEXT_CWE_CATALOG];

  return TAINT_IRIS_NEXT_CWE_CATALOG.filter((entry) => {
    if (threatCwes.has(entry.cwe)) return true;
    if (entry.languages.includes("any")) return true;
    if (languageSet.size === 0) return true;
    return entry.languages.some((language) => languageSet.has(normalizeLanguageName(language)));
  });
}

export function rankCatalogEntries(
  entries: readonly TaintIrisNextCweCatalogEntry[],
  options: {
    context?: RepoContext;
    threatModel?: ThreatModelDocument;
    languages?: readonly string[];
  } = {},
): RankedTaintIrisNextCweCatalogEntry[] {
  const languageSet = collectLanguageSet(options.context, options.languages ?? []);
  const threatCwes = collectThreatCwes(options.threatModel);
  const corpus = buildRelevanceCorpus(options.context, options.threatModel);
  const hasSqlDb = (options.context?.ormOrDb ?? []).some((db) =>
    /sql|postgres|mysql|sqlite|oracle/iu.test(db),
  );
  const hasWeb = options.context
    ? (options.context.frameworks ?? []).length > 0 ||
      (options.context.entryPoints ?? []).length > 0
    : false;
  const sparsePythonContext =
    languageSet.has("python") &&
    (!options.context ||
      (options.context.frameworks ?? []).length +
        (options.context.ormOrDb ?? []).length +
        (options.context.entryPoints ?? []).length <
        2);

  return entries
    .map((entry) => {
      let score = 0;
      const reasons: string[] = [];
      if (threatCwes.has(entry.cwe)) {
        score += 100;
        reasons.push("threat-model CWE");
      }
      if (
        entry.languages.some((language) => languageSet.has(normalizeLanguageName(language))) ||
        (languageSet.size > 0 && entry.languages.includes("any"))
      ) {
        score += 25;
        reasons.push("language match");
      }
      if (entry.languages.includes("any")) {
        score += 5;
        reasons.push("language agnostic");
      }
      if (hasSqlDb && /sql|nosql|second-order/iu.test(entry.taintClass)) {
        score += 35;
        reasons.push("database/ORM context");
      }
      if (hasWeb && WEB_TAINT_CLASSES.has(entry.taintClass)) {
        score += 20;
        reasons.push("web entrypoint context");
      }
      if (sparsePythonContext && PYTHON_SPARSE_CONTEXT_PRIORITY.has(entry.taintClass)) {
        score += 18;
        reasons.push("python sparse-context priority");
      }
      const keywordHits = countKeywordHits(entry, corpus);
      if (keywordHits > 0) {
        score += Math.min(30, keywordHits * 5);
        reasons.push("context keyword overlap");
      }
      return { ...entry, score, reasons };
    })
    .sort((left, right) => {
      if (right.score !== left.score) return right.score - left.score;
      return cweNumeric(left.cwe) - cweNumeric(right.cwe);
    });
}

export function renderCatalogForPrompt(
  entries: readonly TaintIrisNextCweCatalogEntry[],
  options: { maxEntries?: number } = {},
): string {
  const bounded = entries.slice(0, options.maxEntries ?? entries.length);
  const lines = [
    "## CWE Candidate Catalog",
    "The agent must choose CWE themes from this catalog unless it provides customCweRationale.",
    "For every selected catalog CWE, cite at least one source/sink/sanitizer/query signal.",
    "",
  ];

  for (const entry of bounded) {
    const score = "score" in entry ? ` score=${String(entry.score)}` : "";
    lines.push(`- ${entry.cwe}: ${entry.name} [${entry.taintClass}]${score}`);
    lines.push(`  languages: ${entry.languages.join(", ")}`);
    lines.push(`  sources: ${entry.sourceSignals.slice(0, 4).join("; ")}`);
    lines.push(`  sinks: ${entry.sinkSignals.slice(0, 5).join("; ")}`);
    if (entry.sanitizerSignals.length > 0) {
      lines.push(`  sanitizers: ${entry.sanitizerSignals.slice(0, 4).join("; ")}`);
    }
    lines.push(`  structural queries: ${entry.structuralQueries.slice(0, 6).join("; ")}`);
    const hints = formatBackendHints(entry.backendHints);
    if (hints) lines.push(`  backend hints: ${hints}`);
  }

  return lines.join("\n");
}

export function buildStructuralQueriesFromCatalog(
  entries: readonly TaintIrisNextCweCatalogEntry[],
): TaintIrisNextStructuralQuery[] {
  const seen = new Set<string>();
  const queries: TaintIrisNextStructuralQuery[] = [];

  const add = (
    entry: TaintIrisNextCweCatalogEntry,
    role: TaintIrisNextStructuralQuery["role"],
    pattern: string,
  ): void => {
    const trimmed = pattern.trim();
    if (!trimmed) return;
    const key = `${entry.cwe}:${role}:${trimmed.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    queries.push({
      id: `${entry.cwe.toLowerCase()}-${role}-${queries.length + 1}`,
      cwe: entry.cwe,
      taintClass: entry.taintClass,
      role,
      pattern: trimmed,
      languages: entry.languages,
    });
  };

  for (const entry of entries) {
    for (const pattern of entry.sourceSignals) add(entry, "source", pattern);
    for (const pattern of entry.sinkSignals) add(entry, "sink", pattern);
    for (const pattern of entry.sanitizerSignals) add(entry, "sanitizer", pattern);
    for (const pattern of entry.structuralQueries) add(entry, "structural", pattern);
  }

  return queries;
}

export function validateAgentCweSelections(
  selections: readonly TaintIrisNextAgentCweSelection[],
  catalogEntries: readonly TaintIrisNextCweCatalogEntry[] = TAINT_IRIS_NEXT_CWE_CATALOG,
): TaintIrisNextSelectionValidation {
  const catalogIds = new Set(catalogEntries.map((entry) => entry.cwe));
  const accepted: TaintIrisNextSelectionValidation["accepted"] = [];
  const rejected: TaintIrisNextSelectionValidation["rejected"] = [];

  for (const selection of selections) {
    const normalized = normalizeCweId(selection.cwe);
    const knownCatalogCwe = catalogIds.has(normalized);
    const customRationale = selection.customCweRationale?.trim();
    const signalCitations = [
      ...(selection.signalCitations ?? []),
      ...(selection.catalogSignals ?? []),
    ].filter((item) => item.trim().length > 0);

    if (!knownCatalogCwe && !customRationale) {
      rejected.push({
        cwe: normalized,
        reason: "not present in CWE catalog and missing customCweRationale",
      });
      continue;
    }
    if (knownCatalogCwe && signalCitations.length === 0) {
      rejected.push({
        cwe: normalized,
        reason: "catalog CWE selection must cite at least one catalog signal",
      });
      continue;
    }

    accepted.push({ ...selection, cwe: normalized, knownCatalogCwe });
  }

  return { valid: rejected.length === 0, accepted, rejected };
}

const WEB_TAINT_CLASSES = new Set([
  "xss",
  "sql-injection",
  "ldap-injection",
  "header-injection",
  "origin-validation",
  "csrf",
  "file-upload",
  "open-redirect",
  "idor",
  "missing-authorization",
  "incorrect-authorization",
  "mass-assignment",
  "ssrf",
  "nosql-injection",
  "prototype-pollution",
  "regex-injection",
  "ssti",
]);

const PYTHON_SPARSE_CONTEXT_PRIORITY = new Set([
  "command-injection",
  "os-command-injection",
  "sql-injection",
  "path-traversal",
  "ssrf",
  "xss",
  "deserialization",
  "xxe",
  "log-injection",
  "info-exposure",
  "missing-authorization",
  "incorrect-authorization",
  "hardcoded-credentials",
]);

function collectLanguageSet(
  context: RepoContext | undefined,
  languages: readonly string[],
): Set<string> {
  return new Set([...(context?.languages ?? []), ...languages].map(normalizeLanguageName));
}

function normalizeLanguageName(language: string): string {
  const normalized = language.trim().toLowerCase();
  if (normalized === "js") return "javascript";
  if (normalized === "ts") return "typescript";
  if (normalized === "node") return "javascript";
  if (normalized === "c++") return "cpp";
  if (normalized === "c#") return "csharp";
  return normalized;
}

function collectThreatCwes(threatModel: ThreatModelDocument | undefined): Set<string> {
  const cwes = new Set<string>();
  for (const threat of threatModel?.threats ?? []) {
    for (const cwe of threat.relatedCwe ?? []) {
      cwes.add(normalizeCweId(cwe));
    }
  }
  return cwes;
}

function buildRelevanceCorpus(
  context: RepoContext | undefined,
  threatModel: ThreatModelDocument | undefined,
): string {
  const parts = [
    ...(context?.languages ?? []),
    ...(context?.frameworks ?? []),
    ...(context?.authPatterns ?? []),
    ...(context?.sanitizationLibs ?? []),
    ...(context?.ormOrDb ?? []),
    ...(context?.entryPoints ?? []),
  ];
  for (const threat of threatModel?.threats ?? []) {
    parts.push(
      threat.title ?? "",
      threat.description ?? "",
      threat.attackVector ?? "",
      ...(threat.missingMitigations ?? []),
      ...(threat.preconditions ?? []),
    );
  }
  return parts.join(" ").toLowerCase();
}

function countKeywordHits(entry: TaintIrisNextCweCatalogEntry, corpus: string): number {
  if (!corpus) return 0;
  let hits = 0;
  for (const token of [
    entry.taintClass,
    ...entry.sourceSignals,
    ...entry.sinkSignals,
    ...entry.structuralQueries,
  ]) {
    const normalized = token.toLowerCase();
    if (normalized.length >= 3 && corpus.includes(normalized)) hits += 1;
  }
  return hits;
}

function cweNumeric(cwe: string): number {
  const match = cwe.match(/CWE-(\d+)/u);
  return match ? Number.parseInt(match[1]!, 10) : Number.MAX_SAFE_INTEGER;
}

function formatBackendHints(hints: TaintIrisNextBackendHints | undefined): string {
  if (!hints) return "";
  return Object.entries(hints)
    .map(([key, value]) => `${key}: ${value}`)
    .join(" | ");
}
