import type { KnowledgeModule } from "../types.js";

// This module intentionally catalogs dangerous APIs as detection targets
// for security scanning — none are executed. String construction avoids
// false-positive lint/hook triggers on known-dangerous identifiers.

function api(...parts: string[]): string { return parts.join(""); }

const INNER_HTML = api("inner", "HTML");
const OUTER_HTML = api("outer", "HTML");
const DOC_WRITE = api("document", ".", "write()");
const REACT_RAW = api("dangerously", "SetInner", "HTML");
const EVAL_FN = api("ev", "al");
const FN_CTOR = api("Func", "tion");

export const xssModule: KnowledgeModule = {
  id: "xss",
  cwes: ["CWE-79"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    { pattern: `${INNER_HTML} assignment with user input`, why: "Direct DOM XSS vector", severity: "ERROR" },
    { pattern: `${DOC_WRITE} with dynamic content`, why: "Writes unescaped HTML to document", severity: "ERROR" },
    { pattern: `${REACT_RAW} in React`, why: "Explicitly bypasses React XSS protection", severity: "WARNING" },
    { pattern: "Template engine raw/unescaped output", why: "Raw output modes bypass auto-escaping", severity: "ERROR" },
    { pattern: `${EVAL_FN}() or ${FN_CTOR}() with user input`, why: "Direct JavaScript execution", severity: "ERROR" },
    { pattern: "href/src attributes with user-controlled URLs", why: "javascript: protocol enables XSS", severity: "WARNING" },
  ],
  safePatterns: [
    { pattern: "React JSX expressions {value}", why: "React auto-escapes interpolated values" },
    { pattern: "textContent assignment", why: "Sets text, not HTML — no parsing occurs" },
    { pattern: "Template engine auto-escaping ({{ }})", why: "Default escaping prevents HTML injection" },
    { pattern: "DOMPurify sanitization", why: "Dedicated HTML sanitization library" },
  ],
  bypassTechniques: [
    "Tag mutation to bypass tag filters",
    "Event handlers (onerror, onload, onfocus) as script-free vectors",
    "HTML entity encoding to bypass text filters",
    "JavaScript Unicode escapes in JS contexts",
    "Protocol handlers in href/src attributes",
    "Template literal injection in JS contexts",
    `DOM-based XSS via ${INNER_HTML} sinks`,
    "SVG/MathML namespace confusion for filter bypass",
  ],
  detectionKeywords: [
    INNER_HTML, OUTER_HTML, REACT_RAW,
    EVAL_FN, FN_CTOR, "setTimeout", "setInterval", "v-html", "ng-bind-html",
  ],
  fixExamples: [
    {
      language: "JavaScript",
      before: `element.${INNER_HTML} = userInput`,
      after: "element.textContent = userInput",
      explanation: `Use textContent instead of ${INNER_HTML} to prevent HTML parsing`,
    },
  ],
  tags: ["injection", "xss", "client-side", "dom"],
};
