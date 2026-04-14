// NOTE: This file contains DETECTION PATTERNS for a security scanner.
// References to shell functions, SQL queries, etc. are DETECTION TARGETS
// describing what the scanner looks for, not code this file runs.

import type { LanguageProfile } from "./types.js";

export const phpProfile: LanguageProfile = {
  languageId: "PHP",
  aliases: ["php"],
  generalHints: {
    grepPatterns: [
      "\\$_GET",
      "\\$_POST",
      "\\$_REQUEST",
      "\\$_SERVER",
      "\\$_COOKIE",
      "include\\s*\\(",
      "require\\s*\\(",
    ],
    fileHints: [
      "php.ini / .user.ini for security settings",
      "composer.json for dependencies",
      ".env for configuration secrets",
      "routes/ or web.php for Laravel route definitions",
      "config/ for framework configuration",
    ],
    instructions: [
      "Check php.ini settings: display_errors, allow_url_include, register_globals",
      "Look for direct superglobal usage ($_GET, $_POST) vs. framework request objects",
      "Check for disabled functions in php.ini — are dangerous functions still enabled?",
      "Review composer.json for outdated packages with known CVEs",
    ],
  },
  generalAntiHallucination: [
    "Laravel Eloquent with parameter binding is SAFE against SQL injection — do NOT flag Model::where('field', $val)",
    "Laravel Blade templates auto-escape with {{ }} — only flag {!! !!} (raw output)",
    "PDO prepared statements with parameter binding are SAFE against SQL injection",
  ],
  vulnClasses: {
    "type-juggling": {
      sinks: [
        { api: "== loose comparison", risk: "PHP loose comparison: '0e123' == '0e456' evaluates true (scientific notation to 0)", cwes: ["CWE-697"] },
        { api: "strcmp() with non-string input", risk: "strcmp(array, string) returns NULL which == 0 in loose comparison", cwes: ["CWE-697"] },
        { api: "switch/case (loose comparison)", risk: "PHP switch uses loose comparison by default", cwes: ["CWE-697"] },
        { api: "in_array without strict flag", risk: "in_array('0', ['password']) is true due to loose comparison", cwes: ["CWE-697"] },
      ],
      safePatterns: [
        { api: "=== strict comparison", why: "Compares type AND value — no type juggling" },
        { api: "hash_equals() for timing-safe comparison", why: "Constant-time and strict" },
        { api: "in_array($val, $arr, true)", why: "Third arg true enables strict comparison" },
      ],
      investigationHints: {
        grepPatterns: [
          "\\s==\\s",
          "strcmp\\(",
          "in_array\\(",
          "array_search\\(",
          "switch\\s*\\(",
          "hash_equals\\(",
        ],
        fileHints: [
          "Authentication/login handlers",
          "Token verification code",
          "API key validation",
          "Password reset handlers",
        ],
        instructions: [
          "Check authentication code for == instead of === in password/token comparisons",
          "Look for hash comparisons: md5($input) == $stored with == can be bypassed with magic hashes (0e...)",
          "Check in_array and array_search calls — missing strict flag enables type juggling",
        ],
      },
      fewShots: [
        {
          scenario: "Magic hash authentication bypass",
          vulnerableCode: '$hash = md5($user_password);\nif ($hash == $stored_hash) {\n    authenticate($user);\n}',
          explanation: "If $stored_hash is '0e123...' (starts with 0e, rest is digits), PHP interprets it as 0 in scientific notation. Attacker finds a password whose MD5 also starts with '0e' followed by digits — both equal 0.",
        },
      ],
      antiHallucinationExtra: [
        "=== strict comparison is SAFE against type juggling — do NOT flag it",
        "Loose == comparison with hardcoded integer literals (not user input) is low risk",
      ],
    },
    deserialization: {
      sinks: [
        { api: "unserialize($user_input)", risk: "Triggers magic methods (__wakeup, __destruct) enabling RCE via POP chains", cwes: ["CWE-502"] },
        { api: "unserialize with allowed_classes=true (default)", risk: "All classes allowed — POP gadgets available", cwes: ["CWE-502"] },
      ],
      safePatterns: [
        { api: "json_decode($data)", why: "JSON parsing does not trigger code" },
        { api: "unserialize($data, ['allowed_classes' => false])", why: "Blocks POP chains — converts objects to __PHP_Incomplete_Class" },
      ],
      investigationHints: {
        grepPatterns: [
          "unserialize\\(",
          "allowed_classes",
          "serialize\\(",
          "__wakeup",
          "__destruct",
        ],
        fileHints: [
          "Session handling code",
          "Cache implementations",
          "Cookie processing",
        ],
        instructions: [
          "Check if unserialize processes data from cookies, database, or HTTP input",
          "Look for classes with __wakeup or __destruct methods — POP gadget candidates",
          "Check if allowed_classes option is set in unserialize calls (PHP 7.0+)",
        ],
      },
      fewShots: [
        {
          scenario: "Cookie-based deserialization attack",
          vulnerableCode: '$prefs = unserialize(base64_decode($_COOKIE["user_prefs"]));',
          explanation: "User controls cookie value. unserialize instantiates arbitrary classes and triggers __wakeup/__destruct. If a gadget chain exists, attacker achieves RCE.",
        },
      ],
      antiHallucinationExtra: [
        "json_decode() is SAFE — it does not instantiate objects or trigger magic methods",
      ],
    },
    "command-injection": {
      sinks: [
        { api: "system($cmd)", risk: "Shell interpretation of command string", shellInvoking: true, cwes: ["CWE-78"] },
        { api: "passthru($cmd)", risk: "Shell interpretation with raw output", shellInvoking: true, cwes: ["CWE-78"] },
        { api: "shell_exec($cmd) / backtick operator", risk: "Shell interpretation", shellInvoking: true, cwes: ["CWE-78"] },
        { api: "popen($cmd, $mode)", risk: "Shell interpretation", shellInvoking: true, cwes: ["CWE-78"] },
        { api: "proc_open($cmd, ...)", risk: "Shell interpretation if cmd is string", shellInvoking: true, cwes: ["CWE-78"] },
      ],
      safePatterns: [
        { api: "escapeshellarg() wrapping each argument", why: "Escapes shell metacharacters in arguments" },
        { api: "proc_open with array command (PHP 7.4+)", why: "Array form bypasses shell interpretation" },
      ],
      investigationHints: {
        grepPatterns: [
          "\\bsystem\\(",
          "passthru\\(",
          "shell_exec\\(",
          "popen\\(",
          "proc_open\\(",
          "escapeshellarg",
        ],
        fileHints: [
          "Image/file processing handlers",
          "Admin/utility scripts",
          "Cron job handlers",
        ],
        instructions: [
          "PHP has many shell functions — check all of them (system, passthru, shell_exec, popen, proc_open, backticks)",
          "Look for string concatenation with $_GET/$_POST values into command strings",
          "Check if escapeshellarg is applied to EVERY user-controlled part of the command",
        ],
      },
      fewShots: [
        {
          scenario: "Image conversion with user-controlled filename",
          vulnerableCode: '$file = $_POST["filename"];\nsystem("convert " . $file . " output.png");',
          explanation: "$_POST['filename'] is user-controlled. Attacker sends 'img.png; cat /etc/passwd' — shell interprets semicolon.",
        },
      ],
      antiHallucinationExtra: [
        "escapeshellarg() properly applied to all user inputs in a command is sufficient protection",
        "Do NOT flag shell functions with fully hardcoded command strings and no user input",
      ],
    },
    ssrf: {
      sinks: [
        { api: "file_get_contents($url)", risk: "Fetches URL — can reach internal services and use file:// protocol", cwes: ["CWE-918"] },
        { api: "curl with user-controlled CURLOPT_URL", risk: "User-controlled URL in cURL request", cwes: ["CWE-918"] },
        { api: "fopen($url)", risk: "PHP fopen supports URL wrappers when allow_url_fopen is enabled", cwes: ["CWE-918"] },
      ],
      safePatterns: [
        { api: "URL validated against domain allowlist", why: "Restricts reachable hosts" },
        { api: "CURLOPT_PROTOCOLS set to CURLPROTO_HTTPS only", why: "Blocks file:// and other dangerous protocols" },
      ],
      investigationHints: {
        grepPatterns: [
          "file_get_contents\\(",
          "curl_setopt.*CURLOPT_URL",
          "curl_exec\\(",
          "fopen\\(",
          "CURLOPT_FOLLOWLOCATION",
        ],
        fileHints: ["Webhook handlers", "URL preview features", "File import features"],
        instructions: [
          "Check php.ini allow_url_fopen — when enabled, fopen/file_get_contents accept URLs",
          "file_get_contents supports php:// and other wrappers — check if user controls the scheme",
        ],
      },
      fewShots: [
        {
          scenario: "URL preview with SSRF",
          vulnerableCode: '$url = $_GET["url"];\n$content = file_get_contents($url);\necho extractTitle($content);',
          explanation: "User-controlled URL to file_get_contents. Attacker sends url=file:///etc/passwd for local file read or url=http://169.254.169.254/ for cloud metadata.",
        },
      ],
      antiHallucinationExtra: [
        "file_get_contents with a hardcoded file path (not user-controlled) is NOT SSRF",
      ],
    },
    "include-injection": {
      sinks: [
        { api: "include($user_path)", risk: "Runs PHP code from attacker-controlled file path", cwes: ["CWE-98"] },
        { api: "require($user_path)", risk: "Same as include — runs PHP from controlled path", cwes: ["CWE-98"] },
        { api: "include_once/require_once($user_path)", risk: "Same risk — path is still attacker-controlled", cwes: ["CWE-98"] },
      ],
      safePatterns: [
        { api: "include with hardcoded path", why: "Path is constant — no user control" },
        { api: "Allowlist mapping user input to fixed paths", why: "User selects from safe options" },
        { api: "basename() + directory prefix", why: "Strips directory traversal" },
      ],
      investigationHints: {
        grepPatterns: [
          "include\\s*\\(",
          "require\\s*\\(",
          "include_once",
          "require_once",
        ],
        fileHints: ["Routing/dispatcher code", "Template loaders", "Plugin systems"],
        instructions: [
          "Check if include/require paths contain user input",
          "Look for directory traversal: can user input contain ../ ?",
          "With allow_url_include=On, include can fetch remote URLs",
        ],
      },
      fewShots: [
        {
          scenario: "Local file inclusion via page parameter",
          vulnerableCode: '$page = $_GET["page"];\ninclude("templates/" . $page . ".php");',
          explanation: "Attacker sends page=../../config to read sensitive files. With allow_url_include, attacker can include remote PHP code.",
        },
      ],
      antiHallucinationExtra: [
        "include/require with fully hardcoded paths and no user input are SAFE",
      ],
    },
    sqli: {
      sinks: [
        { api: "mysql_query with string concat", risk: "Direct SQL concatenation — classic injection", cwes: ["CWE-89"] },
        { api: "mysqli_query with string interpolation", risk: "User input in SQL string", cwes: ["CWE-89"] },
        { api: "PDO::query with concat", risk: "PDO query without prepared statements", cwes: ["CWE-89"] },
        { api: "DB::raw($user_input) in Laravel", risk: "Raw SQL expression with user input", cwes: ["CWE-89"] },
      ],
      safePatterns: [
        { api: "PDO prepared statements with placeholders", why: "Parameterized query — safe" },
        { api: "mysqli_prepare + bind_param", why: "Parameterized query" },
        { api: "Laravel Eloquent parameter binding", why: "Model::where('field', $val) is parameterized" },
      ],
      investigationHints: {
        grepPatterns: [
          "mysql_query\\(",
          "mysqli_query\\(",
          "->query\\(",
          "DB::raw\\(",
          "->whereRaw\\(",
          "prepare\\(",
        ],
        fileHints: ["Database access layer", "Search implementations", "Report queries"],
        instructions: [
          "Check for string concatenation or interpolation in SQL queries",
          "In Laravel: look for DB::raw(), whereRaw(), selectRaw() with user input",
        ],
      },
      fewShots: [
        {
          scenario: "Search with SQL injection",
          vulnerableCode: '$search = $_GET["q"];\n$result = $db->query("SELECT * FROM products WHERE name LIKE \'%" . $search . "%\'");',
          explanation: "User-controlled $search concatenated into SQL. Attacker sends q=' UNION SELECT password FROM users -- to extract data.",
        },
      ],
      antiHallucinationExtra: [
        "PDO prepared statements with placeholders are SAFE",
        "Laravel Eloquent Model::where('field', $val) is SAFE — only flag raw SQL methods",
      ],
    },
  },
};
