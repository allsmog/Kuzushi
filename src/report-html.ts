import type Database from "better-sqlite3";
import { formatTaintPathForDisplay, summarizeTaintPath } from "./findings/taint-path.js";
import {
  getActionableFindings,
} from "./store.js";

export function generateHtmlReport(
  db: Database.Database,
  repo: string,
  options?: { includeFalsePositives?: boolean; fingerprints?: string[] },
): string {
  const allFindings = getActionableFindings(db, repo, {
    includeFalsePositives: options?.includeFalsePositives ?? true,
    fingerprints: options?.fingerprints,
  });

  const verdictCounts = { tp: 0, fp: 0, needs_review: 0 };
  const severityCounts: Record<string, number> = {};
  const scannerCounts: Record<string, number> = {};
  let totalCost = 0;

  for (const f of allFindings) {
    if (f.verdict === "tp") verdictCounts.tp++;
    else if (f.verdict === "fp") verdictCounts.fp++;
    else verdictCounts.needs_review++;

    const sev = (f.severity || "UNKNOWN").toUpperCase();
    severityCounts[sev] = (severityCounts[sev] ?? 0) + 1;

    const scanner = f.scanner || "unknown";
    scannerCounts[scanner] = (scannerCounts[scanner] ?? 0) + 1;

    totalCost += f.verifyCostUsd ?? 0;
    totalCost += f.pocHarnessCostUsd ?? 0;
  }

  const totalFindings = allFindings.length;

  const findingsJson = JSON.stringify(
    allFindings.map((f) => ({
      fingerprint: f.fingerprint,
      ruleId: f.ruleId,
      filePath: f.filePath,
      startLine: f.startLine,
      severity: (f.severity || "UNKNOWN").toUpperCase(),
      message: f.message,
      verdict: f.verdict,
      confidence: f.confidence,
      rationale: f.rationale,
      scanner: f.scanner || "unknown",
      verifyExploitable: f.verifyExploitable,
      verifyPocPayload: f.verifyPocPayload,
      verifyPocDescription: f.verifyPocDescription,
      verifyAttackVector: f.verifyAttackVector,
      verifyPreconditions: f.verifyPreconditions,
      verifyConfidence: f.verifyConfidence,
      fixPatch: f.fixPatch,
      pocHarnessPath: f.pocHarnessPath,
      pocHarnessSkipped: f.pocHarnessSkipped,
      pocHarnessSkipReason: f.pocHarnessSkipReason,
      pocRunVerdict: f.pocRunVerdict,
      pocRunDurationMs: f.pocRunDurationMs,
      taintPath: f.taintPath
        ? f.taintPath.map((s) => ({
            filePath: s.filePath,
            line: s.line,
            message: s.message,
          }))
        : null,
      taintPathSummary: f.taintPath ? summarizeTaintPath(f.taintPath) : null,
      taintPathDisplay: formatTaintPathForDisplay(f.taintPath),
      proofState: f.proofState ?? null,
      engineProvenance: f.engineProvenance ?? null,
      adjustedScore: f.adjustedScore,
    })),
  );

  const severityJson = JSON.stringify(severityCounts);
  const scannerJson = JSON.stringify(scannerCounts);

  // Build the static HTML portions on the server side where we control content.
  // All dynamic user-facing content is rendered via textContent in the client JS.
  const html = [
    "<!DOCTYPE html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>Kuzushi Report — ${escHtml(repo)}</title>`,
    "<style>",
    CSS_CONTENT,
    "</style>",
    "</head>",
    "<body>",
    '<div id="app">',
    "  <header>",
    '    <div class="header-inner">',
    "      <h1>Kuzushi Security Report</h1>",
    `      <p class="repo-name">${escHtml(repo)}</p>`,
    '      <button id="theme-toggle" aria-label="Toggle theme">Light</button>',
    "    </div>",
    "  </header>",
    "  <main>",
    '    <section class="dashboard">',
    '      <div class="stat-card">',
    `        <span class="stat-value">${totalFindings}</span>`,
    '        <span class="stat-label">Total Findings</span>',
    "      </div>",
    '      <div class="stat-card stat-tp">',
    `        <span class="stat-value">${verdictCounts.tp}</span>`,
    '        <span class="stat-label">True Positives</span>',
    "      </div>",
    '      <div class="stat-card stat-fp">',
    `        <span class="stat-value">${verdictCounts.fp}</span>`,
    '        <span class="stat-label">False Positives</span>',
    "      </div>",
    '      <div class="stat-card stat-nr">',
    `        <span class="stat-value">${verdictCounts.needs_review}</span>`,
    '        <span class="stat-label">Needs Review</span>',
    "      </div>",
    '      <div class="stat-card">',
    `        <span class="stat-value">$${totalCost.toFixed(4)}</span>`,
    '        <span class="stat-label">Total Cost</span>',
    "      </div>",
    "    </section>",
    '    <section class="severity-chart-section">',
    "      <h2>Severity Breakdown</h2>",
    '      <div id="severity-chart" class="bar-chart"></div>',
    "    </section>",
    '    <section class="controls">',
    '      <div class="control-group">',
    '        <label for="filter-verdict">Verdict</label>',
    '        <select id="filter-verdict">',
    '          <option value="all">All</option>',
    '          <option value="tp">True Positive</option>',
    '          <option value="fp">False Positive</option>',
    '          <option value="needs_review">Needs Review</option>',
    "        </select>",
    "      </div>",
    '      <div class="control-group">',
    '        <label for="filter-severity">Severity</label>',
    '        <select id="filter-severity">',
    '          <option value="all">All</option>',
    "        </select>",
    "      </div>",
    '      <div class="control-group">',
    '        <label for="filter-scanner">Scanner</label>',
    '        <select id="filter-scanner">',
    '          <option value="all">All</option>',
    "        </select>",
    "      </div>",
    '      <div class="control-group">',
    '        <label for="sort-by">Sort by</label>',
    '        <select id="sort-by">',
    '          <option value="confidence">Confidence</option>',
    '          <option value="severity">Severity</option>',
    '          <option value="filepath">File Path</option>',
    "        </select>",
    "      </div>",
    '      <div class="control-group count-display">',
    '        <span id="visible-count"></span>',
    "      </div>",
    "    </section>",
    '    <section id="findings-container"></section>',
    "  </main>",
    "  <footer>",
    `    <p>Generated by <strong>Kuzushi</strong> &mdash; ${escHtml(new Date().toISOString())}</p>`,
    "  </footer>",
    "</div>",
    '<div id="toast" class="toast" aria-live="polite"></div>',
    "<script>",
    "(function(){",
    '"use strict";',
    `var FINDINGS = ${findingsJson.replace(/<\//g, "<\\/")};`,
    `var SEVERITY_COUNTS = ${severityJson.replace(/<\//g, "<\\/")};`,
    `var SCANNER_COUNTS = ${scannerJson.replace(/<\//g, "<\\/")};`,
    JS_CONTENT,
    "})();",
    "</script>",
    "</body>",
    "</html>",
    "",
  ];

  return html.join("\n");
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------------------
// CSS (inline)
// ---------------------------------------------------------------------------
const CSS_CONTENT = `
:root {
  --bg: #0f1117;
  --bg-surface: #161822;
  --bg-card: #1c1f2e;
  --bg-card-hover: #232740;
  --text: #e1e4ed;
  --text-secondary: #8b8fa3;
  --text-muted: #5c6078;
  --border: #2a2e42;
  --accent: #6c7ee1;
  --red: #e55b5b;
  --orange: #e5a14f;
  --blue: #5b9ee5;
  --green: #4ec98f;
  --yellow: #e5c94f;
  --font-ui: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --font-mono: "SF Mono", "Fira Code", "Fira Mono", "Roboto Mono", Menlo, Consolas, monospace;
  --radius: 6px;
  --radius-lg: 10px;
}

html.light {
  --bg: #f5f6fa;
  --bg-surface: #ffffff;
  --bg-card: #ffffff;
  --bg-card-hover: #f0f1f5;
  --text: #1a1d2e;
  --text-secondary: #555870;
  --text-muted: #8b8fa3;
  --border: #d8dae5;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--font-ui);
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

#app {
  max-width: 1100px;
  margin: 0 auto;
  padding: 0 16px;
}

header {
  padding: 32px 0 24px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 24px;
}

.header-inner {
  display: flex;
  align-items: baseline;
  gap: 16px;
  flex-wrap: wrap;
}

header h1 {
  font-size: 1.5rem;
  font-weight: 600;
  letter-spacing: -0.01em;
}

.repo-name {
  font-family: var(--font-mono);
  font-size: 0.875rem;
  color: var(--text-secondary);
}

#theme-toggle {
  margin-left: auto;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  padding: 4px 12px;
  border-radius: var(--radius);
  cursor: pointer;
  font-size: 0.75rem;
  font-family: var(--font-ui);
  transition: background 0.15s, color 0.15s;
}

#theme-toggle:hover {
  background: var(--bg-card-hover);
  color: var(--text);
}

.dashboard {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 28px;
}

.stat-card {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 18px 16px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.stat-value {
  font-size: 1.75rem;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}

.stat-label {
  font-size: 0.75rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.stat-tp .stat-value { color: var(--red); }
.stat-fp .stat-value { color: var(--green); }
.stat-nr .stat-value { color: var(--yellow); }

.severity-chart-section {
  margin-bottom: 28px;
}

.severity-chart-section h2 {
  font-size: 1rem;
  font-weight: 600;
  margin-bottom: 12px;
}

.bar-chart {
  display: flex;
  gap: 10px;
  align-items: flex-end;
  height: 120px;
  padding: 8px 0;
}

.bar-col {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  flex: 1;
  min-width: 48px;
}

.bar {
  width: 100%;
  max-width: 56px;
  border-radius: 4px 4px 0 0;
  transition: height 0.3s;
}

.bar-label {
  font-size: 0.7rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.02em;
}

.bar-count {
  font-size: 0.75rem;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}

.controls {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  align-items: flex-end;
  margin-bottom: 20px;
  padding: 14px 16px;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
}

.control-group {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.control-group label {
  font-size: 0.7rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.control-group select {
  font-family: var(--font-ui);
  font-size: 0.8125rem;
  background: var(--bg-card);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 5px 8px;
  cursor: pointer;
}

.count-display {
  margin-left: auto;
  justify-content: flex-end;
}

.count-display span {
  font-size: 0.8125rem;
  color: var(--text-secondary);
  font-variant-numeric: tabular-nums;
}

.finding-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-left: 4px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 18px 20px;
  margin-bottom: 12px;
  transition: background 0.12s;
}

.finding-card:hover {
  background: var(--bg-card-hover);
}

.finding-card.sev-error { border-left-color: var(--red); }
.finding-card.sev-warning { border-left-color: var(--orange); }
.finding-card.sev-note,
.finding-card.sev-info { border-left-color: var(--blue); }

.finding-header {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}

.finding-rule {
  font-family: var(--font-mono);
  font-size: 0.875rem;
  font-weight: 600;
  word-break: break-all;
}

.badge {
  display: inline-block;
  font-size: 0.625rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 2px 8px;
  border-radius: 3px;
}

.badge-tp { background: var(--red); color: #fff; }
.badge-fp { background: var(--green); color: #fff; }
.badge-needs-review { background: var(--yellow); color: #1a1d2e; }
.badge-exploitable { background: var(--red); color: #fff; }
.badge-not-exploitable { background: var(--text-muted); color: #fff; }

.finding-meta {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  font-size: 0.8125rem;
  color: var(--text-secondary);
  margin-bottom: 10px;
}

.finding-meta span {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.meta-label {
  color: var(--text-muted);
}

.finding-location {
  font-family: var(--font-mono);
  font-size: 0.8125rem;
  color: var(--accent);
  word-break: break-all;
  margin-bottom: 10px;
}

.finding-rationale {
  font-size: 0.8125rem;
  line-height: 1.6;
  color: var(--text);
  white-space: pre-wrap;
  margin-bottom: 8px;
}

.finding-actions {
  margin-top: 10px;
}

.copy-btn {
  font-family: var(--font-mono);
  font-size: 0.6875rem;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  padding: 3px 10px;
  border-radius: var(--radius);
  cursor: pointer;
  transition: background 0.12s, color 0.12s;
}

.copy-btn:hover {
  background: var(--bg-card-hover);
  color: var(--text);
}

details {
  margin-top: 8px;
}

details summary {
  font-size: 0.75rem;
  color: var(--text-secondary);
  cursor: pointer;
  user-select: none;
  padding: 4px 0;
}

details summary:hover {
  color: var(--text);
}

details[open] summary {
  margin-bottom: 6px;
}

.detail-content {
  font-size: 0.8125rem;
  color: var(--text);
  padding: 10px 12px;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  white-space: pre-wrap;
  font-family: var(--font-mono);
  line-height: 1.55;
  overflow-x: auto;
}

.toast {
  position: fixed;
  bottom: 20px;
  left: 50%;
  transform: translateX(-50%) translateY(100px);
  background: var(--bg-card);
  color: var(--text);
  border: 1px solid var(--border);
  padding: 8px 18px;
  border-radius: var(--radius);
  font-size: 0.8125rem;
  opacity: 0;
  transition: transform 0.25s, opacity 0.25s;
  pointer-events: none;
  z-index: 999;
}

.toast.show {
  transform: translateX(-50%) translateY(0);
  opacity: 1;
}

footer {
  border-top: 1px solid var(--border);
  padding: 20px 0 32px;
  margin-top: 32px;
  font-size: 0.75rem;
  color: var(--text-muted);
  text-align: center;
}

@media (max-width: 640px) {
  .dashboard {
    grid-template-columns: repeat(2, 1fr);
  }

  .controls {
    flex-direction: column;
    align-items: stretch;
  }

  .count-display {
    margin-left: 0;
  }

  .finding-header {
    flex-direction: column;
    align-items: flex-start;
  }

  .finding-meta {
    flex-direction: column;
    gap: 4px;
  }
}
`;

// ---------------------------------------------------------------------------
// JavaScript (inline) — uses DOM APIs exclusively; no innerHTML
// ---------------------------------------------------------------------------
const JS_CONTENT = `
var SEV_ORDER = { ERROR: 0, WARNING: 1, NOTE: 2, INFO: 3, UNKNOWN: 4 };
var SEV_COLORS = { ERROR: "#e55b5b", WARNING: "#e5a14f", NOTE: "#5b9ee5", INFO: "#5b9ee5", UNKNOWN: "#5c6078" };

// --- Helpers: safe DOM element creation ---
function el(tag, attrs, children) {
  var node = document.createElement(tag);
  if (attrs) {
    for (var k in attrs) {
      if (k === "className") node.className = attrs[k];
      else if (k === "textContent") node.textContent = attrs[k];
      else if (k.indexOf("data-") === 0) node.setAttribute(k, attrs[k]);
      else node.setAttribute(k, attrs[k]);
    }
  }
  if (children) {
    for (var i = 0; i < children.length; i++) {
      if (typeof children[i] === "string") {
        node.appendChild(document.createTextNode(children[i]));
      } else if (children[i]) {
        node.appendChild(children[i]);
      }
    }
  }
  return node;
}

function textSpan(cls, text) {
  var s = document.createElement("span");
  if (cls) s.className = cls;
  s.textContent = text;
  return s;
}

// --- Theme toggle ---
var htmlEl = document.documentElement;
var themeBtn = document.getElementById("theme-toggle");
var savedTheme = null;
try { savedTheme = localStorage.getItem("kuzushi-theme"); } catch(e) {}
if (savedTheme === "light") {
  htmlEl.classList.add("light");
  themeBtn.textContent = "Dark";
}
themeBtn.addEventListener("click", function() {
  htmlEl.classList.toggle("light");
  var isLight = htmlEl.classList.contains("light");
  themeBtn.textContent = isLight ? "Dark" : "Light";
  try { localStorage.setItem("kuzushi-theme", isLight ? "light" : "dark"); } catch(e) {}
});

// --- Severity chart ---
(function buildChart() {
  var container = document.getElementById("severity-chart");
  var entries = Object.entries(SEVERITY_COUNTS);
  if (entries.length === 0) {
    container.textContent = "No findings.";
    return;
  }
  var maxCount = Math.max.apply(null, entries.map(function(e) { return e[1]; }));
  entries.sort(function(a, b) { return (SEV_ORDER[a[0]] || 99) - (SEV_ORDER[b[0]] || 99); });
  for (var i = 0; i < entries.length; i++) {
    var sev = entries[i][0];
    var count = entries[i][1];
    var pct = maxCount > 0 ? (count / maxCount) * 100 : 0;

    var col = el("div", { className: "bar-col" });
    col.appendChild(el("span", { className: "bar-count", textContent: String(count) }));

    var bar = el("div", { className: "bar" });
    bar.style.height = Math.max(pct, 4) + "%";
    bar.style.background = SEV_COLORS[sev] || "#5c6078";
    col.appendChild(bar);

    col.appendChild(el("span", { className: "bar-label", textContent: sev }));
    container.appendChild(col);
  }
})();

// --- Populate filter dropdowns ---
(function populateFilters() {
  var sevSelect = document.getElementById("filter-severity");
  var scanSelect = document.getElementById("filter-scanner");
  Object.keys(SEVERITY_COUNTS).sort(function(a, b) {
    return (SEV_ORDER[a] || 99) - (SEV_ORDER[b] || 99);
  }).forEach(function(sev) {
    var opt = el("option", { value: sev, textContent: sev + " (" + SEVERITY_COUNTS[sev] + ")" });
    sevSelect.appendChild(opt);
  });
  Object.keys(SCANNER_COUNTS).sort().forEach(function(sc) {
    var opt = el("option", { value: sc, textContent: sc + " (" + SCANNER_COUNTS[sc] + ")" });
    scanSelect.appendChild(opt);
  });
})();

// --- Toast ---
var toastEl = document.getElementById("toast");
var toastTimer = null;
function showToast(msg) {
  toastEl.textContent = msg;
  toastEl.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function() { toastEl.classList.remove("show"); }, 2000);
}

// --- Copy to clipboard ---
function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function() { showToast("Fingerprint copied"); });
  } else {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    showToast("Fingerprint copied");
  }
}

// --- Build finding card using DOM APIs ---
var findingsContainer = document.getElementById("findings-container");
var countEl = document.getElementById("visible-count");

function sevClass(severity) {
  var s = (severity || "").toUpperCase();
  if (s === "ERROR") return "sev-error";
  if (s === "WARNING") return "sev-warning";
  if (s === "NOTE" || s === "INFO") return "sev-note";
  return "";
}

function makeBadge(cls, text) {
  return el("span", { className: "badge " + cls, textContent: text });
}

function makeDetailsBlock(summaryText, contentText) {
  var details = document.createElement("details");
  var summary = document.createElement("summary");
  summary.textContent = summaryText;
  details.appendChild(summary);
  var content = el("div", { className: "detail-content", textContent: contentText });
  details.appendChild(content);
  return details;
}

function buildFindingCard(f) {
  var card = el("div", { className: "finding-card " + sevClass(f.severity) });

  // Header
  var header = el("div", { className: "finding-header" });
  header.appendChild(el("span", { className: "finding-rule", textContent: f.ruleId }));

  if (f.verdict === "tp") header.appendChild(makeBadge("badge-tp", "True Positive"));
  else if (f.verdict === "fp") header.appendChild(makeBadge("badge-fp", "False Positive"));
  else header.appendChild(makeBadge("badge-needs-review", "Needs Review"));

  if (f.verifyExploitable === 1) header.appendChild(makeBadge("badge-exploitable", "Exploitable"));
  else if (f.verifyExploitable === 0) header.appendChild(makeBadge("badge-not-exploitable", "Not Exploitable"));

  card.appendChild(header);

  // Meta
  var meta = el("div", { className: "finding-meta" });

  var confSpan = document.createElement("span");
  confSpan.appendChild(el("span", { className: "meta-label", textContent: "Confidence: " }));
  confSpan.appendChild(document.createTextNode((f.confidence * 100).toFixed(0) + "%"));
  meta.appendChild(confSpan);

  var scanSpan = document.createElement("span");
  scanSpan.appendChild(el("span", { className: "meta-label", textContent: "Scanner: " }));
  scanSpan.appendChild(document.createTextNode(f.scanner));
  meta.appendChild(scanSpan);

  var sevSpan = document.createElement("span");
  sevSpan.appendChild(el("span", { className: "meta-label", textContent: "Severity: " }));
  sevSpan.appendChild(document.createTextNode(f.severity));
  meta.appendChild(sevSpan);

  if (f.proofState) {
    var proofSpan = document.createElement("span");
    proofSpan.appendChild(el("span", { className: "meta-label", textContent: "Proof: " }));
    proofSpan.appendChild(document.createTextNode(f.proofState.replace(/_/g, " ")));
    meta.appendChild(proofSpan);
  }

  card.appendChild(meta);

  // Location
  card.appendChild(el("div", { className: "finding-location", textContent: f.filePath + ":" + f.startLine }));

  // Rationale
  card.appendChild(el("div", { className: "finding-rationale", textContent: f.rationale || "No rationale provided." }));

  // Expandable: Taint path
  if (f.taintPathDisplay && f.taintPathDisplay.length > 0) {
    var taintSummary = "Taint Path" + (f.taintPathSummary ? " \\u2014 " + f.taintPathSummary : "");
    card.appendChild(makeDetailsBlock(taintSummary, f.taintPathDisplay.join("\\n")));
  }

  // Expandable: Verification details
  if (f.verifyExploitable != null) {
    var verifyLines = [];
    verifyLines.push(f.verifyExploitable === 1 ? "Status: EXPLOITABLE" : "Status: Not exploitable");
    if (f.verifyConfidence != null) verifyLines.push("Confidence: " + (f.verifyConfidence * 100).toFixed(0) + "%");
    if (f.verifyAttackVector) verifyLines.push("Attack vector: " + f.verifyAttackVector);
    if (f.verifyPreconditions && f.verifyPreconditions.length > 0) {
      verifyLines.push("Preconditions:");
      f.verifyPreconditions.forEach(function(p) { verifyLines.push("  - " + p); });
    }
    if (f.verifyPocDescription) verifyLines.push("\\nPoC description: " + f.verifyPocDescription);
    card.appendChild(makeDetailsBlock("Verification Details", verifyLines.join("\\n")));
  }

  // Expandable: PoC details
  var pocParts = [];
  if (f.verifyPocPayload) pocParts.push("Payload:\\n" + f.verifyPocPayload);
  if (f.pocHarnessPath) pocParts.push("Harness: " + f.pocHarnessPath);
  else if (f.pocHarnessSkipped === 1) pocParts.push("Harness: Skipped (" + (f.pocHarnessSkipReason || "no reason") + ")");
  if (f.pocRunVerdict) {
    var dur = "";
    if (typeof f.pocRunDurationMs === "number") {
      dur = " (" + (f.pocRunDurationMs < 1000 ? f.pocRunDurationMs + "ms" : (f.pocRunDurationMs / 1000).toFixed(1) + "s") + ")";
    }
    pocParts.push("Execution: " + f.pocRunVerdict + dur);
  }
  if (pocParts.length > 0) {
    card.appendChild(makeDetailsBlock("PoC Details", pocParts.join("\\n\\n")));
  }

  // Expandable: Suggested fix
  if (f.fixPatch) {
    card.appendChild(makeDetailsBlock("Suggested Fix", f.fixPatch));
  }

  // Expandable: Engine provenance
  if (f.engineProvenance && f.engineProvenance.length > 0) {
    var epText = f.engineProvenance.map(function(e) { return e.kind + " (" + e.detail + ")"; }).join("\\n");
    card.appendChild(makeDetailsBlock("Engine Provenance", epText));
  }

  // Copy fingerprint button
  var actions = el("div", { className: "finding-actions" });
  var copyBtn = el("button", { className: "copy-btn", textContent: "Copy fingerprint" });
  copyBtn.addEventListener("click", function() { copyToClipboard(f.fingerprint); });
  actions.appendChild(copyBtn);
  card.appendChild(actions);

  return card;
}

function render() {
  var vFilter = document.getElementById("filter-verdict").value;
  var sFilter = document.getElementById("filter-severity").value;
  var scFilter = document.getElementById("filter-scanner").value;
  var sortBy = document.getElementById("sort-by").value;

  var filtered = FINDINGS.filter(function(f) {
    if (vFilter !== "all" && f.verdict !== vFilter) return false;
    if (sFilter !== "all" && f.severity !== sFilter) return false;
    if (scFilter !== "all" && f.scanner !== scFilter) return false;
    return true;
  });

  filtered.sort(function(a, b) {
    if (sortBy === "confidence") return b.confidence - a.confidence;
    if (sortBy === "severity") return (SEV_ORDER[a.severity] || 99) - (SEV_ORDER[b.severity] || 99);
    if (sortBy === "filepath") return a.filePath.localeCompare(b.filePath);
    return 0;
  });

  // Clear container using DOM API
  while (findingsContainer.firstChild) {
    findingsContainer.removeChild(findingsContainer.firstChild);
  }

  for (var i = 0; i < filtered.length; i++) {
    findingsContainer.appendChild(buildFindingCard(filtered[i]));
  }

  countEl.textContent = filtered.length + " of " + FINDINGS.length + " findings";
}

document.getElementById("filter-verdict").addEventListener("change", render);
document.getElementById("filter-severity").addEventListener("change", render);
document.getElementById("filter-scanner").addEventListener("change", render);
document.getElementById("sort-by").addEventListener("change", render);

render();
`;
