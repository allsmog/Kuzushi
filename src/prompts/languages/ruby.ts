// NOTE: This file contains DETECTION PATTERNS for a security scanner.
// The API references are DETECTION TARGETS describing what the scanner
// looks for in scanned codebases, not code this file runs.

import type { LanguageProfile } from "./types.js";

export const rubyProfile: LanguageProfile = {
  languageId: "Ruby",
  aliases: ["ruby", "rb"],
  generalHints: {
    grepPatterns: [
      "class\\s+\\w+Controller",
      "def\\s+\\w+.*params",
      "before_action",
      "protect_from_forgery",
      "permit\\(",
      "render\\s+",
    ],
    fileHints: [
      "Gemfile / Gemfile.lock for dependencies",
      "config/routes.rb for route definitions",
      "config/initializers/ for security configuration",
      "app/controllers/ for request handlers",
      "app/models/ for ActiveRecord models",
      "config/environments/production.rb for production settings",
    ],
    instructions: [
      "Check Gemfile for outdated gems with known CVEs (bundle audit)",
      "Look at config/initializers for security settings (CSRF, session, cookies)",
      "Check strong parameters — are permit calls allowing too many fields?",
      "Review before_action chains — are auth filters applied to all sensitive actions?",
    ],
  },
  generalAntiHallucination: [
    "Rails ActiveRecord with parameterized queries (where(field: val)) is SAFE against SQL injection",
    "Rails ERB auto-escapes with <%= %> — only flag raw() or html_safe usage",
    "Rails CSRF protection is ON by default — only flag if protect_from_forgery is explicitly skipped",
  ],
  vulnClasses: {
    deserialization: {
      sinks: [
        {
          api: "Marshal.load(data)",
          risk: "Deserializes arbitrary Ruby objects — can trigger method_missing or other gadgets for RCE",
          cwes: ["CWE-502"],
        },
        {
          api: "YAML.load(data)",
          risk: "YAML allows Ruby object instantiation via !ruby/object tags",
          cwes: ["CWE-502"],
        },
        {
          api: "YAML.unsafe_load(data)",
          risk: "Explicitly unsafe YAML parsing",
          cwes: ["CWE-502"],
        },
      ],
      safePatterns: [
        { api: "JSON.parse(data)", why: "JSON parsing does not instantiate objects" },
        {
          api: "YAML.safe_load(data)",
          why: "Restricts allowed YAML tags — blocks object instantiation",
        },
        { api: "Psych.safe_load(data, permitted_classes: [...])", why: "Allowlisted classes only" },
      ],
      investigationHints: {
        grepPatterns: [
          "Marshal\\.load",
          "Marshal\\.restore",
          "YAML\\.load\\b",
          "YAML\\.unsafe_load",
          "YAML\\.safe_load",
        ],
        fileHints: [
          "Session storage configuration",
          "Cache serialization code",
          "Job/worker serialization (Sidekiq, Resque)",
          "Cookie handling",
        ],
        instructions: [
          "Check if Marshal.load/YAML.load processes data from cookies, HTTP requests, or message queues",
          "Look at Rails session store — CookieStore uses Marshal by default in older Rails versions",
          "Check Sidekiq/Resque job arguments — are they deserialized from untrusted sources?",
          "In Rails 7+, default session serializer is JSON — check for overrides",
        ],
      },
      fewShots: [
        {
          scenario: "Cookie-based Marshal deserialization",
          vulnerableCode:
            "def load_preferences\n  data = Base64.decode64(cookies[:prefs])\n  @prefs = Marshal.load(data)\nend",
          explanation:
            "User controls cookie value. Marshal.load instantiates arbitrary Ruby objects. Known gadget chains (ERB::Util, Gem::Requirement) enable RCE.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Rails",
          defaults: ["Rails 7+ uses JSON for session serialization by default"],
          pitfalls: [
            "Older Rails versions use Marshal for sessions",
            "Custom session stores may still use Marshal",
          ],
          configChecks: ["Check config.action_dispatch.cookies_serializer setting"],
        },
      ],
      antiHallucinationExtra: [
        "JSON.parse() is SAFE — does not instantiate objects",
        "YAML.safe_load() is SAFE — only flag YAML.load() or YAML.unsafe_load()",
      ],
    },
    "template-injection": {
      sinks: [
        {
          api: "ERB.new(user_str).result",
          risk: "User-controlled ERB template enables Ruby code via <%= %> tags",
          cwes: ["CWE-1336"],
        },
        {
          api: "Haml::Engine.new(user_str).render",
          risk: "Haml template with user-controlled source",
          cwes: ["CWE-1336"],
        },
        {
          api: "Slim::Template.new { user_str }.render",
          risk: "Slim template with user source",
          cwes: ["CWE-1336"],
        },
        { api: "send(user_method)", risk: "Calls arbitrary method on object", cwes: ["CWE-470"] },
      ],
      safePatterns: [
        {
          api: "render template: 'file', locals: { var: user_data }",
          why: "Template file is fixed, user data is a variable",
        },
        {
          api: "ERB.new(constant_string).result_with_hash(user: data)",
          why: "Template is constant",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "ERB\\.new\\(",
          "Haml::Engine",
          "\\beval\\(",
          "\\.send\\(",
          "public_send\\(",
          "render\\s+inline:",
        ],
        fileHints: [
          "Custom template rendering code",
          "Email/notification templates",
          "Report generation",
        ],
        instructions: [
          "Check if the template source (not data) comes from user input",
          "Look for render inline: in Rails controllers — this compiles user string as ERB",
          "Check for send/public_send with user-controlled method names",
        ],
      },
      fewShots: [
        {
          scenario: "Rails render inline with user input",
          vulnerableCode:
            "def preview\n  template = params[:template]\n  render inline: template\nend",
          explanation:
            "render inline: compiles the string as ERB. Attacker sends template with embedded Ruby code tags for RCE.",
        },
      ],
      antiHallucinationExtra: [
        "render template: 'file.html.erb' with user data as local variables is SAFE",
        "Rails ERB auto-escapes with <%= %> for XSS — but if user controls the TEMPLATE itself, it is SSTI",
      ],
    },
    "mass-assignment": {
      sinks: [
        {
          api: "Model.new(params) without strong params",
          risk: "Attacker can set any model attribute including admin, role, password",
          cwes: ["CWE-915"],
        },
        {
          api: "Model.update(params) without permit",
          risk: "Unfiltered params update any column",
          cwes: ["CWE-915"],
        },
        {
          api: "Overly broad permit (permit!)",
          risk: "permit! allows ALL parameters — defeats strong params",
          cwes: ["CWE-915"],
        },
      ],
      safePatterns: [
        {
          api: "params.require(:model).permit(:field1, :field2)",
          why: "Strong parameters — explicit allowlist",
        },
        { api: "attr_accessible in older Rails (< 4)", why: "Model-level attribute allowlist" },
      ],
      investigationHints: {
        grepPatterns: [
          "\\.permit\\(",
          "\\.permit!",
          "params\\[",
          "attr_accessible",
          "attr_protected",
        ],
        fileHints: [
          "Controller actions (create, update)",
          "Private parameter filtering methods",
          "API controllers",
        ],
        instructions: [
          "Check every create/update action — are params filtered through permit?",
          "Look for permit! (bang version) — this allows ALL parameters",
          "Check if sensitive fields (admin, role, email_verified) are excluded from permit lists",
          "In API controllers, check if params are used directly without strong params",
        ],
      },
      fewShots: [
        {
          scenario: "Admin privilege escalation via mass assignment",
          vulnerableCode:
            "def update\n  @user = User.find(params[:id])\n  @user.update(params[:user].permit!)\nend",
          explanation:
            "permit! allows all parameters. Attacker sends user[admin]=true to escalate privileges.",
        },
      ],
      antiHallucinationExtra: [
        "params.require(:model).permit(:specific_fields) is SAFE — properly filtered",
        "Strong parameters in Rails 4+ are the standard protection — do NOT flag properly filtered params",
      ],
    },
    "command-injection": {
      sinks: [
        {
          api: "system(cmd) single-arg",
          risk: "Shell interpretation of command string",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "backtick operator `cmd`",
          risk: "Shell interpretation",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "%x{cmd}",
          risk: "Shell interpretation (alternative syntax)",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "IO.popen(cmd)",
          risk: "Shell interpretation",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "Open3.capture3(cmd) single string",
          risk: "Shell interpretation for single string arg",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
      ],
      safePatterns: [
        {
          api: "system('cmd', arg1, arg2)",
          why: "Multi-arg system bypasses shell — arguments passed directly",
        },
        { api: "Open3.capture3('cmd', arg1, arg2)", why: "Multi-arg form bypasses shell" },
        { api: "Shellwords.escape(user_input)", why: "Proper shell escaping" },
      ],
      investigationHints: {
        grepPatterns: ["\\bsystem\\(", "IO\\.popen", "Open3\\.", "Shellwords"],
        fileHints: ["Rake tasks", "Background job processors", "File processing handlers"],
        instructions: [
          "Check for string interpolation in backtick commands",
          "system() with a single string argument uses shell — multi-arg form is safe",
          "Look for Shellwords.escape — if applied to all user input, it is safe",
        ],
      },
      fewShots: [
        {
          scenario: "Backtick command with interpolation",
          vulnerableCode:
            "def convert(filename)\n  output = `convert #{filename} output.png`\n  output\nend",
          explanation:
            "filename interpolated into shell command via backticks. Attacker sends 'img.png; rm -rf /' — shell interprets the semicolon.",
        },
      ],
      antiHallucinationExtra: [
        "system('cmd', arg1, arg2) multi-arg form is SAFE — no shell interpretation",
        "Do NOT flag shell commands with hardcoded strings and no user input",
      ],
    },
  },
};
