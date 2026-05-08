// NOTE: This file contains DETECTION PATTERNS for a security scanner.
// The API references (subprocess, pickle, etc.) are DETECTION TARGETS
// describing what the scanner looks for in scanned codebases,
// not code this file executes.

import type { LanguageProfile } from "./types.js";

export const pythonProfile: LanguageProfile = {
  languageId: "Python",
  aliases: ["python", "py", "python3"],
  generalHints: {
    grepPatterns: [
      "import\\s+subprocess",
      "import\\s+os",
      "from\\s+flask",
      "from\\s+django",
      "from\\s+fastapi",
      "@app\\.route",
      "def\\s+\\w+.*request",
    ],
    fileHints: [
      "settings.py / config.py for Django/Flask configuration",
      "requirements.txt / pyproject.toml for dependency versions",
      "urls.py for Django route definitions",
      "views.py / routes.py for request handlers",
      "manage.py and management/commands/ for Django management commands",
      "celery tasks (tasks.py) for background job handlers",
    ],
    instructions: [
      "Check Django settings for DEBUG, ALLOWED_HOSTS, SECRET_KEY, SECURE_* flags",
      "Look for Flask routes with methods=['POST'] and raw request.data access",
      "Check FastAPI Depends() chains for missing auth dependencies",
      "Inspect Celery task arguments — are they user-controlled?",
    ],
  },
  generalAntiHallucination: [
    "Django ORM parameterized queries are SAFE against SQL injection — do NOT flag Model.objects.filter(field=value)",
    "Flask/Django built-in template rendering auto-escapes by default — only flag |safe or Markup() usage",
    "Python json.loads() is SAFE — it does not run code during deserialization",
  ],
  vulnClasses: {
    "command-injection": {
      sinks: [
        {
          api: "os.system(cmd)",
          risk: "Full shell interpretation of cmd string",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "os.popen(cmd)",
          risk: "Shell interpretation, returns pipe",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "subprocess with shell=True",
          risk: "Shell interpretation when shell=True",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "subprocess with list args, shell=False",
          risk: "SAFE against metachar injection when passed as list",
          shellInvoking: false,
          cwes: ["CWE-78"],
        },
      ],
      safePatterns: [
        {
          api: "subprocess.run([cmd, arg1, arg2])",
          why: "List args with shell=False (default) prevents metachar injection",
        },
        {
          api: "shlex.quote() wrapping user input",
          why: "Proper shell escaping before insertion into command string",
        },
        {
          api: "subprocess with all hardcoded arguments",
          why: "No attacker-controlled data in arguments",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "os\\.system\\(",
          "os\\.popen\\(",
          "subprocess\\.",
          "shell=True",
          "shlex\\.quote",
        ],
        fileHints: [
          "Django management commands (management/commands/)",
          "Celery tasks (tasks.py)",
          "Scripts that invoke external tools (ffmpeg, imagemagick, git)",
        ],
        instructions: [
          "Check if subprocess calls use shell=True — this is the critical distinction in Python",
          "Look for f-strings or .format() constructing shell command strings with user data",
          "Check Django management commands for subprocess calls with user-influenced arguments",
          "Inspect Celery task definitions — their arguments may come from untrusted web requests",
        ],
      },
      fewShots: [
        {
          scenario: "Django management command with shell injection",
          vulnerableCode:
            'def handle(self, *args, **options):\n    db_name = options["database"]\n    subprocess.call(f"pg_dump {db_name}", shell=True)',
          explanation:
            "db_name from command options flows to shell via f-string with shell=True. If db_name is user-influenced, attacker injects shell commands.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Django",
          defaults: ["Django ORM avoids most need for shell commands"],
          pitfalls: [
            "Management commands often use subprocess for database/migration tools",
            "Settings values (DB name, paths) may flow to subprocess calls",
          ],
          configChecks: ["Check DATABASES config for names flowing to shell commands"],
        },
      ],
      antiHallucinationExtra: [
        "subprocess.run() with a list argument and shell=False (the default) is SAFE against metachar injection — do NOT flag it",
        "Do NOT flag subprocess calls where all arguments are hardcoded strings with no user data",
      ],
    },
    deserialization: {
      sinks: [
        {
          api: "pickle.loads/load",
          risk: "Runs arbitrary Python code during deserialization via __reduce__",
          cwes: ["CWE-502"],
        },
        {
          api: "yaml.load() without SafeLoader",
          risk: "YAML !!python/object tags run arbitrary code",
          cwes: ["CWE-502"],
        },
        {
          api: "shelve.open()",
          risk: "Uses pickle internally — same code-exec risk",
          cwes: ["CWE-502"],
        },
        {
          api: "marshal.loads()",
          risk: "Can run code via crafted bytecode objects",
          cwes: ["CWE-502"],
        },
        {
          api: "dill.loads()",
          risk: "Extended pickle — same arbitrary code execution",
          cwes: ["CWE-502"],
        },
        {
          api: "jsonpickle.decode()",
          risk: "Deserializes Python objects from JSON — code-exec via crafted payloads",
          cwes: ["CWE-502"],
        },
      ],
      safePatterns: [
        {
          api: "json.loads(data)",
          why: "JSON parsing does NOT run code — safe for untrusted input",
        },
        { api: "yaml.safe_load(data)", why: "SafeLoader rejects dangerous YAML tags" },
        { api: "yaml.load(data, Loader=SafeLoader)", why: "Explicitly safe loader" },
      ],
      investigationHints: {
        grepPatterns: [
          "pickle\\.",
          "yaml\\.load\\(",
          "yaml\\.unsafe_load",
          "shelve\\.",
          "marshal\\.",
          "dill\\.",
          "jsonpickle\\.",
          "SafeLoader",
        ],
        fileHints: [
          "Cache backends (Redis/Memcached serialization)",
          "Celery result backends and message serializers",
          "Session storage implementations",
          "ML model loading code (joblib, torch.load)",
        ],
        instructions: [
          "Check if pickle/yaml.load processes data from HTTP requests, message queues, or uploaded files",
          "Look at Celery configuration — CELERY_ACCEPT_CONTENT and CELERY_RESULT_SERIALIZER settings control serialization format",
          "Check ML model loading — torch.load and joblib.load use pickle internally",
          "Inspect cache get/set operations — some cache backends serialize with pickle by default",
        ],
      },
      fewShots: [
        {
          scenario: "Flask endpoint deserializing uploaded data unsafely",
          vulnerableCode:
            '@app.route("/import", methods=["POST"])\ndef import_data():\n    data = pickle.loads(request.data)\n    return process(data)',
          explanation:
            "request.data is attacker-controlled. Unsafe deserialization runs arbitrary code via __reduce__ method in crafted payloads.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Django",
          defaults: ["Django sessions use JSON serializer by default since 1.6"],
          pitfalls: [
            "SESSION_SERIALIZER can be changed to PickleSerializer",
            "Cache backends may use pickle",
          ],
          configChecks: [
            "Check SESSION_SERIALIZER in settings.py",
            "Check CACHES backend configuration",
          ],
        },
        {
          framework: "Flask",
          defaults: ["Flask session cookies are signed and use JSON by default"],
          pitfalls: [
            "Flask-Caching with certain backends may use pickle",
            "Custom session stores may use pickle",
          ],
          configChecks: ["Check CACHE_TYPE configuration"],
        },
      ],
      antiHallucinationExtra: [
        "json.loads() is SAFE — it does NOT run code. Never flag JSON deserialization as unsafe",
        "yaml.safe_load() is SAFE — only flag yaml.load() without SafeLoader or yaml.unsafe_load()",
        "torch.load with weights_only=True is safe (PyTorch 2.6+)",
      ],
    },
    "template-injection": {
      sinks: [
        {
          api: "jinja2.Template(user_str).render()",
          risk: "User-controlled Jinja2 template — SSTI enables RCE via __class__.__mro__ chain",
          cwes: ["CWE-1336"],
        },
        {
          api: "render_template_string(user_str)",
          risk: "Flask helper that compiles user string as Jinja2 template",
          cwes: ["CWE-1336"],
        },
        {
          api: "mako.template.Template(user_str)",
          risk: "Mako templates allow Python code execution",
          cwes: ["CWE-1336"],
        },
      ],
      safePatterns: [
        {
          api: "render_template('file.html', var=user_data)",
          why: "User data passed as variable, not as template source — Jinja2 auto-escapes",
        },
        {
          api: "Jinja2 SandboxedEnvironment",
          why: "Restricts template capabilities (but can be bypassed — verify version)",
        },
      ],
      investigationHints: {
        grepPatterns: ["render_template_string", "Template\\(", "from_string\\(", "Environment\\("],
        fileHints: [
          "View functions that render templates",
          "Email template generation code",
          "Report/PDF generation code",
        ],
        instructions: [
          "Check if user input is passed as the template string (first arg) vs. as a template variable",
          "render_template('file.html', name=user_input) is SAFE — render_template_string(user_input) is DANGEROUS",
          "Look for custom template rendering in email/notification systems",
        ],
      },
      fewShots: [
        {
          scenario: "Flask SSTI via render_template_string",
          vulnerableCode:
            '@app.route("/greet")\ndef greet():\n    name = request.args.get("name")\n    return render_template_string(f"Hello {name}!")',
          explanation:
            "User-controlled name is interpolated into the template string before Jinja2 compiles it. Attacker sends {{config.items()}} to extract secrets or chain to RCE.",
        },
      ],
      antiHallucinationExtra: [
        "render_template('template.html', var=user_input) is SAFE — user data is a variable, not the template",
        "Jinja2 auto-escapes HTML by default — this prevents XSS but NOT SSTI (different vulnerability class)",
      ],
    },
    ssrf: {
      sinks: [
        {
          api: "requests.get/post(url)",
          risk: "URL from user input can target internal services",
          cwes: ["CWE-918"],
        },
        {
          api: "urllib.request.urlopen(url)",
          risk: "No URL validation — can reach internal endpoints",
          cwes: ["CWE-918"],
        },
        {
          api: "httpx.get/post(url)",
          risk: "Same risk as requests — user-controlled URL",
          cwes: ["CWE-918"],
        },
        {
          api: "aiohttp.ClientSession.get(url)",
          risk: "Async HTTP client with user-controlled URL",
          cwes: ["CWE-918"],
        },
      ],
      safePatterns: [
        {
          api: "URL validated against allowlist of domains",
          why: "Only permitted domains are reachable",
        },
        {
          api: "Requests to hardcoded URLs with user data in body/params",
          why: "URL is fixed, user controls only payload",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "requests\\.(get|post|put|delete|head)\\(",
          "urlopen\\(",
          "httpx\\.",
          "aiohttp",
        ],
        fileHints: [
          "Webhook handlers",
          "URL preview/unfurl features",
          "Proxy or redirect endpoints",
          "File download/import from URL features",
        ],
        instructions: [
          "Check if the URL parameter comes from user input (request args, form data, database record from user)",
          "Look for URL parsing that can be bypassed (checking startswith('http') does not prevent http://internal)",
          "Check for redirect following — requests follows redirects by default, which can bypass URL checks",
          "Cloud metadata: can the URL reach 169.254.169.254 (AWS), metadata.google.internal, etc.?",
        ],
      },
      fewShots: [
        {
          scenario: "Webhook URL validation bypass",
          vulnerableCode:
            '@app.route("/webhook", methods=["POST"])\ndef register_webhook():\n    url = request.json["callback_url"]\n    if not url.startswith("https://"):\n        abort(400)\n    requests.get(url)',
          explanation:
            "startswith check is insufficient — attacker sends https://169.254.169.254/latest/meta-data/ to reach AWS metadata endpoint.",
        },
      ],
      antiHallucinationExtra: [
        "Requests to hardcoded URLs with only user-controlled query params or body data are NOT SSRF",
        "Internal service-to-service calls with no user-controlled URL component are NOT SSRF",
      ],
    },
    "race-condition": {
      sinks: [
        {
          api: "Shared mutable state without locks",
          risk: "Concurrent access to shared dict/list/object from multiple threads or async tasks",
          cwes: ["CWE-362"],
        },
        {
          api: "TOCTOU on filesystem",
          risk: "Check-then-act on file existence/permissions with race window",
          cwes: ["CWE-367"],
        },
        {
          api: "Django get_or_create without select_for_update",
          risk: "Race between check and create in concurrent requests",
          cwes: ["CWE-362"],
        },
      ],
      safePatterns: [
        { api: "threading.Lock / asyncio.Lock around shared state", why: "Proper synchronization" },
        {
          api: "Django select_for_update()",
          why: "Database-level row locking prevents concurrent modification",
        },
        {
          api: "Atomic database operations (F() expressions, update())",
          why: "Single SQL statement is atomic",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "threading\\.Thread",
          "asyncio\\.gather",
          "concurrent\\.futures",
          "get_or_create",
          "select_for_update",
        ],
        fileHints: [
          "Background task/worker code",
          "Payment or balance-modifying endpoints",
          "User registration or resource allocation code",
        ],
        instructions: [
          "Look for read-modify-write patterns on shared state without locking",
          "Check Django views that modify balances/counters — are they using F() expressions or select_for_update?",
          "In async code, check if shared state is modified across await points without asyncio.Lock",
        ],
      },
      fewShots: [
        {
          scenario: "Double-spend via Django balance update race",
          vulnerableCode:
            "def withdraw(request):\n    account = Account.objects.get(user=request.user)\n    if account.balance >= amount:\n        account.balance -= amount\n        account.save()",
          explanation:
            "Two concurrent requests both read the same balance, both pass the check, both subtract — double withdrawal. Fix: use select_for_update() or F() expressions.",
        },
      ],
      antiHallucinationExtra: [
        "Single-threaded Python code (no threading/asyncio) is NOT vulnerable to race conditions via the GIL (but IO-bound async code CAN race)",
        "Django ORM operations that use F() expressions are atomic at the database level",
      ],
    },
  },
};
