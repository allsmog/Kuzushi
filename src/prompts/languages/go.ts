// NOTE: This file contains DETECTION PATTERNS for a security scanner.
// The API references are DETECTION TARGETS describing what the scanner
// looks for in scanned codebases, not code this file executes.

import type { LanguageProfile } from "./types.js";

export const goProfile: LanguageProfile = {
  languageId: "Go",
  aliases: ["go", "golang"],
  generalHints: {
    grepPatterns: [
      "func\\s+\\w+Handler",
      "http\\.HandleFunc",
      "gin\\.Context",
      "echo\\.Context",
      "r\\.FormValue",
      "c\\.Param\\(",
      "go\\s+func",
    ],
    fileHints: [
      "go.mod for dependencies and Go version",
      "main.go / cmd/server/ for entry points and route registration",
      "middleware/ for auth and validation middleware",
      "internal/handler/ or handlers/ for HTTP handler functions",
    ],
    instructions: [
      "Check go.mod for known vulnerable dependency versions",
      "Look at router setup (mux, gin, echo) for missing middleware on routes",
      "Check for goroutine usage in request handlers — shared state access patterns",
      "Inspect error handling — Go returns errors, check if they are silently discarded",
    ],
  },
  generalAntiHallucination: [
    "Go database/sql with ? placeholders uses parameterized queries — SAFE against SQL injection",
    "GORM .Where(\"field = ?\", val) is parameterized — only flag raw SQL string concatenation",
    "Go html/template auto-escapes by default — only flag text/template with HTML output",
  ],
  vulnClasses: {
    "race-condition": {
      sinks: [
        { api: "Shared map/slice accessed from multiple goroutines", risk: "Go maps are NOT concurrent-safe — concurrent read+write causes panic or corruption", cwes: ["CWE-362"] },
        { api: "Global variable modified in goroutine", risk: "Package-level var accessed without sync", cwes: ["CWE-362"] },
        { api: "Read-modify-write without mutex", risk: "counter++ across goroutines is not atomic", cwes: ["CWE-362"] },
      ],
      safePatterns: [
        { api: "sync.Mutex / sync.RWMutex around shared state", why: "Proper locking" },
        { api: "sync.Map for concurrent map access", why: "Concurrent-safe map implementation" },
        { api: "atomic.AddInt64 / atomic.Load*", why: "Lock-free atomic operations" },
        { api: "Channel-based communication", why: "Share memory by communicating, don't communicate by sharing memory" },
      ],
      investigationHints: {
        grepPatterns: [
          "go\\s+func",
          "sync\\.Mutex",
          "sync\\.RWMutex",
          "sync\\.Map",
          "atomic\\.",
          "chan\\s+",
        ],
        fileHints: [
          "HTTP handler functions that spawn goroutines",
          "Background worker/job processing code",
          "Cache implementations with concurrent access",
        ],
        instructions: [
          "Look for 'go func()' inside HTTP handlers — does the goroutine access request-scoped or shared state?",
          "Check if package-level maps are accessed from request handlers (concurrent HTTP requests = concurrent goroutines)",
          "Run 'go vet -race' mentally: any variable written by one goroutine and read by another without sync?",
          "Check for TOC-TOU patterns: checking map key existence, then acting on it without holding lock",
        ],
      },
      fewShots: [
        {
          scenario: "Concurrent map write in HTTP handler",
          vulnerableCode: 'var cache = make(map[string]string)\n\nfunc handler(w http.ResponseWriter, r *http.Request) {\n    key := r.FormValue("key")\n    cache[key] = r.FormValue("value") // concurrent write\n}',
          explanation: "HTTP handlers run in separate goroutines. Concurrent writes to the unsynchronized map cause a runtime panic (fatal error: concurrent map writes) or silent data corruption.",
        },
      ],
      antiHallucinationExtra: [
        "Go maps are NOT concurrent-safe even for reads during concurrent writes — this is a real bug, not theoretical",
        "A single-goroutine function that is never called concurrently is NOT a race condition",
        "sync.Once is safe — do NOT flag it as a race condition",
      ],
    },
    "command-injection": {
      sinks: [
        { api: 'exec.Command("sh", "-c", userStr)', risk: "Shell interpretation of user-controlled string", shellInvoking: true, cwes: ["CWE-78"] },
        { api: 'exec.Command("bash", "-c", userStr)', risk: "Shell interpretation via bash", shellInvoking: true, cwes: ["CWE-78"] },
        { api: "exec.Command(userBinary, args...)", risk: "User controls which binary is executed", shellInvoking: false, cwes: ["CWE-78"] },
      ],
      safePatterns: [
        { api: 'exec.Command("fixed-binary", userArg)', why: "Binary is fixed, user controls only arguments — no shell interpretation" },
        { api: "exec.CommandContext with fixed binary", why: "Context adds timeout but same safety as Command" },
      ],
      investigationHints: {
        grepPatterns: [
          'exec\\.Command\\(',
          "exec\\.CommandContext\\(",
          '"sh".*"-c"',
          '"bash".*"-c"',
        ],
        fileHints: [
          "Utility functions that invoke system commands",
          "CI/CD pipeline handlers",
          "Git operation wrappers",
        ],
        instructions: [
          'Check if exec.Command uses "sh" or "bash" with "-c" flag — this enables shell interpretation',
          "If the binary name itself comes from user input, it is command injection regardless of shell",
          "exec.Command with a fixed binary and user args is safe against shell metachar injection (no shell involved)",
        ],
      },
      fewShots: [
        {
          scenario: "Git clone with user-controlled URL via shell",
          vulnerableCode: 'func cloneRepo(url string) error {\n    cmd := exec.Command("sh", "-c", "git clone "+url)\n    return cmd.Run()\n}',
          explanation: 'url is user-controlled and concatenated into a shell command via "sh -c". Attacker sends "; rm -rf /" as URL. Fix: use exec.Command("git", "clone", url) without shell.',
        },
      ],
      antiHallucinationExtra: [
        'exec.Command("fixed-binary", userArgs...) without "sh"/"-c" is NOT vulnerable to shell metachar injection',
        "Do NOT flag exec.Command with all hardcoded arguments",
      ],
    },
    ssrf: {
      sinks: [
        { api: "http.Get(url) / http.Post(url, ...)", risk: "User-controlled URL can target internal services", cwes: ["CWE-918"] },
        { api: "http.NewRequest + client.Do", risk: "URL from user input in request construction", cwes: ["CWE-918"] },
        { api: "resty.New().R().Get(url)", risk: "Resty client with user-controlled URL", cwes: ["CWE-918"] },
      ],
      safePatterns: [
        { api: "URL validated against allowlist before request", why: "Only permitted hosts reachable" },
        { api: "Hardcoded base URL with user-controlled path/params", why: "User cannot change the target host" },
      ],
      investigationHints: {
        grepPatterns: [
          "http\\.Get\\(",
          "http\\.Post\\(",
          "http\\.NewRequest\\(",
          "client\\.Do\\(",
          "url\\.Parse\\(",
        ],
        fileHints: [
          "Webhook/callback handlers",
          "URL fetching or proxy endpoints",
          "File download features",
        ],
        instructions: [
          "Check if URL comes from r.FormValue, r.URL.Query(), or request body",
          "Go http.Client follows redirects by default (up to 10) — this can bypass URL validation",
          "Check for cloud metadata access: can user URL reach 169.254.169.254?",
          "Look for url.Parse followed by checking scheme/host — can be bypassed with URL parser tricks",
        ],
      },
      fewShots: [
        {
          scenario: "Proxy endpoint with open redirect",
          vulnerableCode: 'func proxyHandler(w http.ResponseWriter, r *http.Request) {\n    target := r.URL.Query().Get("url")\n    resp, _ := http.Get(target)\n    io.Copy(w, resp.Body)\n}',
          explanation: "User-controlled URL is fetched server-side. Attacker sends url=http://169.254.169.254/latest/meta-data/ to access cloud metadata.",
        },
      ],
      antiHallucinationExtra: [
        "http.Get with hardcoded URL and no user-controlled components is NOT SSRF",
        "Internal microservice calls with URLs from config (not user input) are NOT SSRF",
      ],
    },
    "template-injection": {
      sinks: [
        { api: "text/template with user-controlled template string", risk: "Go templates can call methods — user controls which methods via {{.Method}}", cwes: ["CWE-1336"] },
        { api: "html/template with user-controlled template string", risk: "Same as text/template but with HTML escaping — methods still callable", cwes: ["CWE-1336"] },
      ],
      safePatterns: [
        { api: "Template files with user data as variables", why: "User controls data, not template structure" },
        { api: "html/template with hardcoded template string", why: "Template is constant, only data varies" },
      ],
      investigationHints: {
        grepPatterns: [
          'template\\.New\\(',
          'template\\.Must\\(',
          '\\.Parse\\(',
          'template\\.ParseFiles\\(',
        ],
        fileHints: [
          "Template rendering in HTTP handlers",
          "Email or notification template generation",
        ],
        instructions: [
          "Check if the template string (not the data) comes from user input",
          "template.New().Parse(userInput) is dangerous — template.New().Parse(constant).Execute(w, userData) is safe",
          "Go templates can call exported methods on the data object — check what methods are accessible",
        ],
      },
      fewShots: [
        {
          scenario: "User-controlled Go template string",
          vulnerableCode: 'func render(w http.ResponseWriter, r *http.Request) {\n    tpl := r.FormValue("template")\n    t, _ := template.New("").Parse(tpl)\n    t.Execute(w, data)\n}',
          explanation: "User controls the template string. Attacker sends {{.SensitiveField}} to extract data or chains method calls for further access.",
        },
      ],
      antiHallucinationExtra: [
        "Go html/template auto-escapes HTML by default — this prevents XSS but NOT template injection",
        "Template files loaded from disk with user data as variables are SAFE",
      ],
    },
    "crypto-misuse": {
      sinks: [
        { api: "crypto/md5 or crypto/sha1 for passwords", risk: "Weak hash — fast to brute force", cwes: ["CWE-328"] },
        { api: "crypto/des", risk: "DES is broken — 56-bit key length", cwes: ["CWE-327"] },
        { api: "math/rand for security-sensitive values", risk: "Predictable PRNG — not cryptographically secure", cwes: ["CWE-338"] },
        { api: "Hardcoded keys/secrets in source", risk: "Secrets in code are extractable", cwes: ["CWE-798"] },
        { api: "crypto/aes in ECB mode", risk: "ECB reveals patterns in plaintext", cwes: ["CWE-327"] },
      ],
      safePatterns: [
        { api: "crypto/rand for random bytes", why: "Cryptographically secure RNG" },
        { api: "golang.org/x/crypto/bcrypt or argon2", why: "Proper password hashing" },
        { api: "crypto/aes with GCM mode", why: "Authenticated encryption" },
      ],
      investigationHints: {
        grepPatterns: [
          "crypto/md5",
          "crypto/sha1",
          "crypto/des",
          "math/rand",
          "crypto/rand",
          "bcrypt",
          "argon2",
          "aes\\.NewCipher",
          "cipher\\.NewGCM",
        ],
        fileHints: [
          "Authentication and password handling code",
          "Token/session generation code",
          "Encryption/decryption utilities",
        ],
        instructions: [
          "Check if md5/sha1 is used for password hashing vs. checksums (checksums are fine)",
          "Check if math/rand is seeded with crypto/rand or used for security tokens (use crypto/rand instead)",
          "Look for AES usage — is it using GCM/CTR mode or insecure ECB mode?",
        ],
      },
      fewShots: [
        {
          scenario: "Math/rand for session token generation",
          vulnerableCode: 'import "math/rand"\n\nfunc generateToken() string {\n    b := make([]byte, 32)\n    for i := range b {\n        b[i] = byte(rand.Intn(256))\n    }\n    return hex.EncodeToString(b)\n}',
          explanation: "math/rand is a predictable PRNG. If an attacker knows or guesses the seed (often time-based), they can predict all future tokens. Use crypto/rand.Read instead.",
        },
      ],
      antiHallucinationExtra: [
        "md5/sha1 for content checksums or cache keys is NOT a vulnerability — only flag for password hashing or authentication",
        "math/rand for non-security purposes (shuffling, jitter, load balancing) is NOT a vulnerability",
      ],
    },
  },
};
