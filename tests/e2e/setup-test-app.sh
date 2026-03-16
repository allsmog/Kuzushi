#!/usr/bin/env bash
# setup-test-app.sh — Creates a deliberately vulnerable test app for E2E testing.
# Usage: ./setup-test-app.sh [target_dir]

set -euo pipefail

TARGET_DIR="${1:-/tmp/kuzushi-test-app}"

echo "Setting up test app at ${TARGET_DIR} ..."

rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR/routes"
mkdir -p "$TARGET_DIR/.kuzushi"

# ─── package.json ─────────────────────────────────────────────────────
cat > "$TARGET_DIR/package.json" << 'PKGJSON'
{
  "name": "kuzushi-test-app",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "express": "4"
  }
}
PKGJSON

# ─── server.js — Express app with multiple vulnerability types ────────
# CWE-79: Reflected XSS (semgrep detects this)
# CWE-78: Command injection via child_process.exec (semgrep detects this)
# Two exec() calls with same source req.query.cmd → tests Phase 3A dedup
cat > "$TARGET_DIR/server.js" << 'SERVERJS'
const express = require("express");
const { exec } = require("child_process");

const app = express();
app.use(express.json());

// CWE-79: Reflected XSS — unsanitized query param in HTML output.
app.get("/profile", (req, res) => {
  const username = req.query.username;
  res.send("<h1>Welcome, " + username + "</h1>");
});

// CWE-78: OS Command Injection — user input in exec() call.
// First command using req.query.cmd (source A -> sink 1).
app.get("/run", (req, res) => {
  const cmd = req.query.cmd;
  exec("sh -c " + cmd, (err, stdout) => {
    res.json({ output: stdout });
  });
});

// CWE-78: OS Command Injection — same source flows to a second sink (Phase 3A dedup test).
// Second command using req.query.cmd (source A -> sink 2).
app.get("/run-bg", (req, res) => {
  const cmd = req.query.cmd;
  exec("nohup " + cmd, (err, stdout) => {
    res.json({ started: true });
  });
});

// CWE-79: Second XSS — different route, same pattern.
app.get("/greet", (req, res) => {
  const name = req.query.name;
  res.send("<p>Hello " + name + "!</p>");
});

// CWE-78: Command injection with different source (req.body.host).
app.post("/ping", (req, res) => {
  const host = req.body.host;
  exec("ping -c 1 " + host, (err, stdout) => {
    res.json({ result: stdout });
  });
});

app.listen(3000, () => {
  console.log("Listening on :3000");
});
SERVERJS

# ─── routes/auth.js — Auth bypass (CWE-287) ──────────────────────────
cat > "$TARGET_DIR/routes/auth.js" << 'AUTHJS'
const express = require("express");
const router = express.Router();

// CWE-287: Improper authentication — no password verification.
router.post("/login", (req, res) => {
  const { username } = req.body;
  // Missing password check — any username is accepted.
  if (username) {
    req.session = { user: username, admin: username === "admin" };
    res.json({ ok: true, user: username });
  } else {
    res.status(400).json({ error: "Username required" });
  }
});

// CWE-639: Authorization bypass via user-controlled key.
router.get("/admin", (req, res) => {
  const isAdmin = req.query.admin === "true";
  if (isAdmin) {
    res.json({ secret: "admin-data" });
  } else {
    res.status(403).json({ error: "Forbidden" });
  }
});

module.exports = router;
AUTHJS

# ─── routes/upload.js — Path traversal (CWE-22) ─────────────────────
cat > "$TARGET_DIR/routes/upload.js" << 'UPLOADJS'
const express = require("express");
const fs = require("fs");
const path = require("path");
const router = express.Router();

// CWE-22: Path traversal — user controls filename without sanitization.
router.get("/download", (req, res) => {
  const filename = req.query.file;
  const filepath = path.join("/var/uploads", filename);
  if (fs.existsSync(filepath)) {
    res.sendFile(filepath);
  } else {
    res.status(404).json({ error: "Not found" });
  }
});

// CWE-22: Path traversal — writing files with user-controlled name.
router.post("/upload", (req, res) => {
  const filename = req.body.filename;
  const content = req.body.content;
  const dest = path.join("/var/uploads", filename);
  fs.writeFileSync(dest, content);
  res.json({ ok: true, path: dest });
});

module.exports = router;
UPLOADJS

# ─── dead-code.js — Unreachable functions (Phase 3B test) ─────────────
# Uses child_process.exec and eval — patterns semgrep reliably detects.
# These functions are NEVER called from any route or entry point.
cat > "$TARGET_DIR/dead-code.js" << 'DEADJS'
const { exec } = require("child_process");

// This function contains command injection but is NEVER called from any route,
// entry point, or event listener. It is dead code.
function unusedShellHelper(userInput) {
  exec("ls " + userInput, (err, stdout) => {
    return stdout;
  });
}

// Another dead function — also unreachable. Uses eval with user input.
function unusedEvalHelper(expression) {
  return eval(expression);
}

// This export exists but nothing imports dead-code.js.
module.exports = { unusedShellHelper, unusedEvalHelper };
DEADJS

# ─── .kuzushi/precedents.txt — Phase 1C test ─────────────────────────
cat > "$TARGET_DIR/.kuzushi/precedents.txt" << 'PREC'
## Architectural Precedents
- Express helmet middleware is NOT installed
- No CSRF protection middleware is configured
- No input sanitization library is used
- child_process.exec is used directly in route handlers

## Signal Quality Criteria
- Command injection via child_process.exec with user input is always high-signal
- Reflected XSS with unsanitized query params in res.send is always high-signal
- Path traversal with user-controlled filenames joined via path.join is high-signal
PREC

# ─── .kuzushi/config.json — Enable all new features ──────────────────
cat > "$TARGET_DIR/.kuzushi/config.json" << 'CONFIG'
{
  "model": "openai:qwen3:8b",
  "triageModel": "openai:qwen3:8b",
  "verifyModel": "openai:qwen3:8b",
  "agentRuntimeConfig": {
    "apiKey": "ollama",
    "baseUrl": "http://localhost:11434/v1"
  },
  "scanners": ["semgrep"],
  "verify": true,
  "confidenceCalibration": true,
  "trajectoryMemory": true,
  "incrementalCache": true,
  "triageMaxTurns": 5,
  "verifyMaxTurns": 5,
  "triageConcurrency": 1,
  "triageBatchSize": 1,
  "maxTriageRetries": 2,
  "maxVerifyRetries": 1,
  "auditLog": true
}
CONFIG

# ─── Initialize git repo (needed for diff-review and regression tests) ─
(
  cd "$TARGET_DIR"
  git init -q
  git add -A
  git commit -q -m "initial: vulnerable test app"
)

echo "Test app created at ${TARGET_DIR}"
echo "Files:"
find "$TARGET_DIR" -type f -not -path '*/.git/*' | sort | sed "s|${TARGET_DIR}/|  |"
