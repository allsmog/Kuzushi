// NOTE: This file contains DETECTION PATTERNS for a security scanner.
// The API references are DETECTION TARGETS describing what the scanner
// looks for in scanned codebases, not code this file executes.

import type { LanguageProfile } from "./types.js";

export const jstsProfile: LanguageProfile = {
  languageId: "JavaScript/TypeScript",
  aliases: ["javascript", "typescript", "js", "ts", "jsx", "tsx", "node", "nodejs"],
  generalHints: {
    grepPatterns: [
      "require\\(",
      "import\\s+.*from",
      "express\\(",
      "app\\.(get|post|put|delete|patch|use)\\(",
      "createServer\\(",
      "next\\.config",
      "getServerSideProps",
      "getStaticProps",
      "React\\.createElement",
      "useEffect\\(",
    ],
    fileHints: [
      "package.json for dependency versions and scripts",
      ".env / .env.local for environment variable definitions",
      "next.config.js / next.config.mjs for Next.js configuration",
      "middleware.ts / middleware.js for Next.js/Express middleware",
      "server.js / app.js / index.js for Express server setup",
      "routes/ or pages/ directories for route definitions",
      "lib/auth or utils/auth for authentication logic",
    ],
    instructions: [
      "Run npm audit / pnpm audit mentally — check package.json for known-vulnerable dependency versions",
      "Review middleware chains in Express (app.use ordering) and Next.js (middleware.ts matcher config)",
      "Check for missing CSRF protection on state-changing routes",
      "Inspect .env files for secrets and verify they are in .gitignore",
      "Look for API routes that bypass authentication middleware",
    ],
  },
  generalAntiHallucination: [
    "Parameterized queries via ORMs (Prisma, Sequelize, TypeORM, Knex with bindings) are SAFE against SQL injection — do NOT flag them",
    "React JSX interpolation {variable} auto-escapes by default — this prevents XSS unless dangerouslySetInnerHTML is used",
    "parseInt() and Number() are type coercion, NOT injection vectors — do NOT flag them as dangerous sinks",
  ],
  vulnClasses: {
    "prototype-pollution": {
      sinks: [
        { api: "lodash.merge(target, userObj)", risk: "Deep merge copies __proto__ or constructor.prototype properties from attacker-controlled object", cwes: ["CWE-1321"] },
        { api: "lodash.defaultsDeep(target, userObj)", risk: "Recursive default assignment traverses __proto__ chain from untrusted input", cwes: ["CWE-1321"] },
        { api: "_.extend(target, userObj) / $.extend(true, target, userObj)", risk: "Deep extend copies prototype-polluting keys from user objects", cwes: ["CWE-1321"] },
        { api: "Object.assign(target, userObj) with nested user objects", risk: "Shallow copy can still overwrite properties if target is Object.prototype via crafted key path", cwes: ["CWE-1321"] },
        { api: "Custom recursive merge/deepMerge functions", risk: "Hand-rolled deep merge without __proto__/constructor filtering", cwes: ["CWE-1321"] },
      ],
      safePatterns: [
        { api: "Object.assign({}, userObj)", why: "Shallow copy into a new empty object — does not pollute existing prototypes" },
        { api: "structuredClone(userObj)", why: "Structured clone strips prototype chain — safe deep copy" },
        { api: "JSON.parse(JSON.stringify(obj))", why: "Round-trip strips __proto__ keys and prototype references" },
        { api: "Map/Set instead of plain objects for dynamic keys", why: "Map does not have a prototype chain vulnerable to pollution" },
      ],
      investigationHints: {
        grepPatterns: [
          "\\.merge\\(",
          "\\.extend\\(",
          "Object\\.assign\\(",
          "defaultsDeep\\(",
          "deepMerge\\(",
          "deepExtend\\(",
          "__proto__",
          "constructor\\[",
        ],
        fileHints: [
          "Utility/helper files with merge or extend functions",
          "Configuration loaders that merge user-supplied config objects",
          "API route handlers that spread or merge request body into objects",
          "Middleware that parses and merges query parameters or headers",
        ],
        instructions: [
          "Check if the source object in any merge/extend call originates from user input (req.body, req.query, parsed JSON)",
          "Look for custom deep merge utilities — do they filter __proto__, constructor, and prototype keys?",
          "Check lodash version — versions before 4.17.12 have known prototype pollution in merge/defaultsDeep",
          "Inspect config merging logic where user-supplied options are merged with defaults",
        ],
      },
      fewShots: [
        {
          scenario: "Lodash merge with user-controlled request body",
          vulnerableCode: 'const _ = require("lodash");\napp.post("/settings", (req, res) => {\n  const defaults = { theme: "light", lang: "en" };\n  const settings = _.merge(defaults, req.body);\n  res.json(settings);\n});',
          explanation: 'req.body is attacker-controlled. Sending {"__proto__": {"isAdmin": true}} pollutes Object.prototype so every object in the process inherits isAdmin=true.',
        },
      ],
      frameworkGuidance: [
        {
          framework: "Express",
          defaults: ["Express does not provide built-in protection against prototype pollution"],
          pitfalls: ["Body parsers (express.json()) pass parsed JSON directly — __proto__ keys are preserved", "Middleware that merges req.body into config objects"],
          configChecks: ["Check if body parser has a reviver that strips __proto__ keys"],
        },
      ],
      antiHallucinationExtra: [
        "Object.assign({}, obj) with a fresh empty target is SAFE — it does not pollute prototypes",
        "Shallow spread ({...obj}) is SAFE against prototype pollution — only deep recursive operations are dangerous",
        "JSON.parse does NOT preserve __proto__ as a prototype link — it becomes a regular property name",
      ],
    },
    "command-injection": {
      sinks: [
        { api: "child_process.exec(cmd)", risk: "Passes cmd to /bin/sh — full shell interpretation of user-controlled strings", shellInvoking: true, cwes: ["CWE-78"] },
        { api: "child_process.execSync(cmd)", risk: "Synchronous shell execution — same risk as exec", shellInvoking: true, cwes: ["CWE-78"] },
        { api: "child_process.spawn(cmd, { shell: true })", risk: "spawn with shell option enables shell interpretation", shellInvoking: true, cwes: ["CWE-78"] },
        { api: "eval(userStr)", risk: "Executes arbitrary JavaScript code from string", shellInvoking: false, cwes: ["CWE-94"] },
        { api: "new Function(userStr)", risk: "Compiles and executes arbitrary JavaScript from string", shellInvoking: false, cwes: ["CWE-94"] },
        { api: "vm.runInNewContext(userStr)", risk: "Executes code in a V8 context — sandbox escapes are well-documented", shellInvoking: false, cwes: ["CWE-94"] },
      ],
      safePatterns: [
        { api: "child_process.execFile(bin, [arg1, arg2])", why: "No shell invocation — arguments are passed directly to the binary" },
        { api: "child_process.spawn(bin, [arg1, arg2])", why: "Without shell option, no shell metacharacter interpretation" },
        { api: "All hardcoded arguments to exec/spawn", why: "No attacker-controlled data in command or arguments" },
      ],
      investigationHints: {
        grepPatterns: [
          "child_process",
          "\\.exec\\(",
          "execSync\\(",
          "\\.spawn\\(",
          "shell:\\s*true",
          "\\beval\\(",
          "new Function\\(",
        ],
        fileHints: [
          "Build scripts and task runners",
          "API routes that invoke system tools (ffmpeg, imagemagick, git, pandoc)",
          "CI/CD helper scripts",
          "File conversion or processing endpoints",
        ],
        instructions: [
          "Check if exec/execSync calls use template literals or string concatenation with user-supplied data",
          "Look for spawn calls with the shell option set to true — this negates spawn's argument-array safety",
          "Inspect eval() and new Function() — trace the string argument back to its source",
          "Check for indirect eval via setTimeout(string) or setInterval(string) with user data",
        ],
      },
      fewShots: [
        {
          scenario: "Express route using exec with template literal from user input",
          vulnerableCode: 'const { exec } = require("child_process");\napp.get("/convert", (req, res) => {\n  const filename = req.query.file;\n  exec(`convert ${filename} output.png`, (err, stdout) => {\n    res.send(stdout);\n  });\n});',
          explanation: "filename comes from req.query.file (attacker-controlled). Sending 'img.png; cat /etc/passwd' executes the injected command via shell interpretation.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Express",
          defaults: ["Express does not invoke shell commands — but route handlers often do for file processing"],
          pitfalls: ["Routes that call exec/execSync with user-controlled query params or body fields", "Middleware that shells out to system tools for request processing"],
          configChecks: ["Check for helmet or other security middleware that might limit exposure"],
        },
      ],
      antiHallucinationExtra: [
        "child_process.execFile() and spawn() without shell option are SAFE against shell metacharacter injection — do NOT flag them",
        "Do NOT flag exec/spawn calls where all arguments are hardcoded strings with no user data",
        "setTimeout(function, ms) with a function reference (not string) is SAFE — only setTimeout('string') is dangerous",
      ],
    },
    ssrf: {
      sinks: [
        { api: "fetch(url)", risk: "Native fetch with user-controlled URL can target internal services", cwes: ["CWE-918"] },
        { api: "axios.get(url) / axios(url)", risk: "HTTP client with user-controlled URL — follows redirects by default", cwes: ["CWE-918"] },
        { api: "http.request(url)", risk: "Node.js built-in HTTP client with no URL validation", cwes: ["CWE-918"] },
        { api: "got(url)", risk: "HTTP client with user-controlled URL — follows redirects by default", cwes: ["CWE-918"] },
        { api: "node-fetch(url)", risk: "Polyfill fetch with user-controlled URL", cwes: ["CWE-918"] },
      ],
      safePatterns: [
        { api: "Hardcoded URLs with user data in body/params only", why: "URL is fixed — user controls only payload, not destination" },
        { api: "URL validated against allowlist of domains/IPs", why: "Only permitted destinations are reachable" },
        { api: "Outbound proxy with internal network blocking", why: "Network-level control prevents access to internal services" },
      ],
      investigationHints: {
        grepPatterns: [
          "\\bfetch\\(",
          "axios\\(",
          "axios\\.(get|post|put|delete)\\(",
          "http\\.request\\(",
          "https\\.request\\(",
          "\\bgot\\(",
          "node-fetch",
        ],
        fileHints: [
          "Webhook registration or callback endpoints",
          "URL preview/unfurl/screenshot features",
          "Proxy or redirect endpoints",
          "File download or import-from-URL features",
          "API routes that fetch external resources on behalf of users",
        ],
        instructions: [
          "Check if the URL parameter originates from user input (req.query, req.body, database field set by user)",
          "Look for URL validation that can be bypassed — startsWith('https://') does NOT prevent https://169.254.169.254",
          "Check if the HTTP client follows redirects — a redirect from an allowed domain to an internal IP bypasses allowlists",
          "Cloud metadata: can the URL reach 169.254.169.254 (AWS), metadata.google.internal (GCP), or 169.254.169.254 (Azure)?",
          "Check for DNS rebinding — URL resolves to allowed IP on first check but internal IP on actual request",
        ],
      },
      fewShots: [
        {
          scenario: "Proxy endpoint passing user-supplied URL to fetch",
          vulnerableCode: 'app.get("/proxy", async (req, res) => {\n  const url = req.query.url;\n  const response = await fetch(url);\n  const data = await response.text();\n  res.send(data);\n});',
          explanation: "url is entirely attacker-controlled from req.query.url. Attacker sends http://169.254.169.254/latest/meta-data/iam/security-credentials/ to steal cloud credentials.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Next.js",
          defaults: ["Next.js API routes and Server Actions can make server-side HTTP requests"],
          pitfalls: ["getServerSideProps that fetch user-supplied URLs", "API routes acting as proxy endpoints", "Image optimization (next/image) with unvalidated remote patterns"],
          configChecks: ["Check next.config.js images.remotePatterns for overly broad domain patterns"],
        },
        {
          framework: "Express",
          defaults: ["Express does not make outbound HTTP requests by default"],
          pitfalls: ["Proxy middleware (http-proxy-middleware) with user-controlled target", "Routes that fetch URLs from request parameters"],
          configChecks: ["Check proxy middleware configuration for target URL validation"],
        },
      ],
      antiHallucinationExtra: [
        "Requests to hardcoded URLs with only user-controlled query params or body data are NOT SSRF",
        "Internal service-to-service calls with no user-controlled URL component are NOT SSRF",
        "next/image remote patterns are validated at build time — but overly broad patterns (e.g., **) weaken this protection",
      ],
    },
    xss: {
      sinks: [
        { api: "dangerouslySetInnerHTML={{ __html: userStr }}", risk: "React escape hatch — injects raw HTML without escaping", cwes: ["CWE-79"] },
        { api: "element.innerHTML = userStr", risk: "Sets raw HTML content from user-controlled string", cwes: ["CWE-79"] },
        { api: "document.write(userStr)", risk: "Writes raw HTML to document from user-controlled string", cwes: ["CWE-79"] },
        { api: "v-html directive (Vue)", risk: "Vue directive that renders raw HTML without escaping", cwes: ["CWE-79"] },
        { api: "jQuery .html(userStr)", risk: "Sets inner HTML of element from user-controlled string", cwes: ["CWE-79"] },
        { api: "res.send(userStr) without Content-Type", risk: "Express sends user string as HTML by default if no Content-Type set", cwes: ["CWE-79"] },
      ],
      safePatterns: [
        { api: "React JSX interpolation {variable}", why: "React auto-escapes interpolated values — prevents XSS" },
        { api: "element.textContent = userStr", why: "textContent sets text, not HTML — no parsing or execution" },
        { api: "DOMPurify.sanitize(html)", why: "Sanitizes HTML by removing dangerous tags and attributes" },
        { api: "Vue {{ variable }} interpolation", why: "Vue auto-escapes template interpolations" },
      ],
      investigationHints: {
        grepPatterns: [
          "dangerouslySetInnerHTML",
          "\\.innerHTML\\s*=",
          "document\\.write\\(",
          "v-html",
          "\\.html\\(",
          "res\\.send\\(",
        ],
        fileHints: [
          "React components that render user-generated content (comments, profiles, messages)",
          "Server-side rendered templates (EJS, Pug, Handlebars) with unescaped output",
          "API endpoints that return HTML responses",
          "Rich text editors and markdown renderers",
        ],
        instructions: [
          "Check every use of dangerouslySetInnerHTML — trace __html value to its source and check for sanitization",
          "Look for innerHTML assignments in vanilla JS or jQuery — is the value user-controlled?",
          "In server-rendered templates, check for unescaped output (<%- in EJS, !{} in Pug, {{{triple}}} in Handlebars)",
          "Check if DOMPurify or similar sanitizer is applied before rendering user HTML",
        ],
      },
      fewShots: [
        {
          scenario: "React component rendering user content with dangerouslySetInnerHTML",
          vulnerableCode: 'function Comment({ body }) {\n  return <div dangerouslySetInnerHTML={{ __html: body }} />;\n}',
          explanation: "body comes from user-submitted comment. Attacker submits '<img src=x onerror=alert(document.cookie)>' which executes in other users' browsers.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "React",
          defaults: ["JSX interpolation {var} auto-escapes all values — XSS-safe by default"],
          pitfalls: ["dangerouslySetInnerHTML bypasses auto-escaping", "Creating elements from user-controlled HTML strings", "Server-side rendering with unsanitized HTML injection"],
          configChecks: ["Search for all dangerouslySetInnerHTML usages and verify sanitization"],
        },
        {
          framework: "Next.js",
          defaults: ["Inherits React's auto-escaping for JSX interpolation"],
          pitfalls: ["API routes returning HTML with user input via res.send()", "Server Components rendering unsanitized user HTML", "Middleware that modifies response HTML"],
          configChecks: ["Check Content-Security-Policy headers in next.config.js or middleware"],
        },
        {
          framework: "Express",
          defaults: ["Express does not auto-escape — template engines handle escaping"],
          pitfalls: ["res.send(userInput) returns HTML content type by default", "EJS <%- unescaped %> output", "Pug !{unescaped} output"],
          configChecks: ["Check template engine configuration for auto-escape settings", "Check helmet CSP headers"],
        },
      ],
      antiHallucinationExtra: [
        "React JSX {variable} is SAFE — auto-escaping prevents XSS. Do NOT flag JSX interpolation",
        "textContent and innerText are SAFE — they do not parse HTML",
        "Setting element.src or element.href to user input is a different risk (open redirect / resource injection), NOT XSS via innerHTML",
      ],
    },
    "template-injection": {
      sinks: [
        { api: "eval() with template literal containing user data", risk: "Template literal evaluated as code — arbitrary code execution", cwes: ["CWE-94"] },
        { api: "ejs.render(userStr)", risk: "User-controlled EJS template string enables server-side code execution", cwes: ["CWE-1336"] },
        { api: "ejs.compile(userStr)", risk: "Compiles user-controlled string as EJS template", cwes: ["CWE-1336"] },
        { api: "pug.compile(userStr)", risk: "Compiles user-controlled Pug template — code execution via unbuffered code", cwes: ["CWE-1336"] },
        { api: "pug.render(userStr)", risk: "Renders user-controlled Pug template string", cwes: ["CWE-1336"] },
        { api: "nunjucks.renderString(userStr)", risk: "Renders user-controlled Nunjucks template — RCE via template constructs", cwes: ["CWE-1336"] },
        { api: "Handlebars.compile(userStr)", risk: "User-controlled Handlebars template — prototype-access gadgets", cwes: ["CWE-1336"] },
      ],
      safePatterns: [
        { api: "ejs.render(templateFile, { data: userData })", why: "Template from file, user data passed as variables — not as template source" },
        { api: "res.render('template', { user: userData })", why: "Express render with file template and user data as context variables" },
        { api: "Template files with user-supplied variables only", why: "User controls data, not the template structure" },
      ],
      investigationHints: {
        grepPatterns: [
          "ejs\\.render\\(",
          "ejs\\.compile\\(",
          "pug\\.compile\\(",
          "pug\\.render\\(",
          "nunjucks\\.renderString\\(",
          "Handlebars\\.compile\\(",
          "renderString\\(",
        ],
        fileHints: [
          "Email template generation code",
          "Report or PDF generation endpoints",
          "CMS or user-customizable page renderers",
          "Admin tools that allow template editing",
        ],
        instructions: [
          "Check if user input is passed as the template string (first arg) vs. as template variables (data/context arg)",
          "ejs.render(templateFile, { var: userInput }) is SAFE — ejs.render(userInput) is DANGEROUS",
          "Look for template rendering in email/notification systems where users control message templates",
          "Check for admin-only template editors — even admin-restricted SSTI can be critical if admin accounts are compromised",
        ],
      },
      fewShots: [
        {
          scenario: "EJS render with user-controlled template string",
          vulnerableCode: 'app.post("/preview", (req, res) => {\n  const template = req.body.template;\n  const html = ejs.render(template, { user: req.user });\n  res.send(html);\n});',
          explanation: "template comes from req.body (attacker-controlled). Attacker sends '<%= process.mainModule.require(\"child_process\").execSync(\"id\") %>' to achieve RCE.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Express",
          defaults: ["Express res.render() uses file-based templates by default"],
          pitfalls: ["Manually calling ejs.render/pug.render with user-supplied strings bypasses file-based safety", "Template engines configured with user-controlled template directories"],
          configChecks: ["Check view engine configuration in app.set('view engine')", "Verify template directory is not user-writable"],
        },
      ],
      antiHallucinationExtra: [
        "res.render('template.ejs', { data: userInput }) is SAFE — user data is a variable, not the template",
        "Template literals (`Hello ${name}`) in JavaScript source code are NOT template injection — they are evaluated at write time, not runtime from user input",
        "Handlebars by default escapes HTML in {{ }} — only {{{ }}} is unescaped. But SSTI is about code execution, not just XSS",
      ],
    },
    "auth-bypass": {
      sinks: [
        { api: "Express route without auth middleware", risk: "Route handler accessible without authentication check", cwes: ["CWE-306"] },
        { api: "JWT.verify with algorithms: ['none']", risk: "Algorithm confusion allows forged tokens with 'none' algorithm", cwes: ["CWE-287"] },
        { api: "JWT.verify without specifying algorithms", risk: "May accept unexpected algorithms including 'none' or HMAC with RSA public key", cwes: ["CWE-287"] },
        { api: "Weak session secret", risk: "Predictable or hardcoded session secret enables session forgery", cwes: ["CWE-798"] },
        { api: "Missing CSRF protection on state-changing routes", risk: "Cross-site requests can perform actions as authenticated user", cwes: ["CWE-352"] },
      ],
      safePatterns: [
        { api: "JWT.verify(token, secret, { algorithms: ['HS256'] })", why: "Explicit algorithm list prevents algorithm confusion attacks" },
        { api: "Auth middleware applied via app.use() before all protected routes", why: "Centralized auth enforcement" },
        { api: "Next.js middleware.ts with route matcher for auth", why: "Middleware intercepts requests before route handlers" },
      ],
      investigationHints: {
        grepPatterns: [
          "app\\.(get|post|put|delete|patch)\\(",
          "router\\.(get|post|put|delete|patch)\\(",
          "jwt\\.verify\\(",
          "jwt\\.sign\\(",
          "algorithms:",
          "session.*secret",
          "passport\\.",
        ],
        fileHints: [
          "Route definition files (routes/, app.js, server.js)",
          "Authentication middleware files",
          "JWT configuration and token verification code",
          "Session configuration (express-session setup)",
          "Next.js middleware.ts for route protection",
        ],
        instructions: [
          "List all routes and check which ones have auth middleware applied — look for routes that should be protected but are not",
          "Check JWT verification: does it specify an explicit algorithms array? Is the secret strong and from environment variables?",
          "Look for route ordering issues — auth middleware must come before the routes it protects in Express",
          "Check for admin routes or API endpoints that are accidentally public",
          "Inspect Next.js middleware.ts matcher config — does it cover all protected paths?",
        ],
      },
      fewShots: [
        {
          scenario: "Express route missing auth middleware",
          vulnerableCode: 'app.use("/api", authMiddleware);\n// ... many lines later ...\napp.get("/internal/admin/users", (req, res) => {\n  res.json(getAllUsers());\n});',
          explanation: "The /internal/admin/users route is defined outside the /api path prefix where authMiddleware is applied. It is publicly accessible without authentication.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Express",
          defaults: ["Express has no built-in authentication — all auth is via middleware"],
          pitfalls: ["Auth middleware applied to /api does not protect routes outside that prefix", "Route ordering matters — routes defined before middleware bypass it", "Router-level middleware does not apply to routes on different routers"],
          configChecks: ["Verify auth middleware is applied to all sensitive route groups", "Check session configuration for secure cookie flags (httpOnly, secure, sameSite)"],
        },
        {
          framework: "Next.js",
          defaults: ["Next.js middleware.ts can protect routes at the edge before they execute"],
          pitfalls: ["middleware.ts matcher config may not cover all protected routes", "API routes can be accessed directly, bypassing page-level auth checks", "Server Actions may lack their own auth verification"],
          configChecks: ["Check middleware.ts matcher for route coverage gaps", "Verify API routes independently check authentication"],
        },
      ],
      antiHallucinationExtra: [
        "A route behind a properly configured auth middleware is NOT an auth bypass — verify the middleware is actually applied to that route",
        "JWT with a strong secret and explicit algorithm list is SAFE — do NOT flag properly configured JWT verification",
        "Next.js middleware.ts protecting a path does NOT mean individual API routes under that path skip their own auth — they may have redundant checks, which is fine",
      ],
    },
  },
};
