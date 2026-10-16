#!/usr/bin/env node
// The DevEx journeys drive the real shell, so a journey that sends a page
// digit the Workbench keymap does not bind cannot reach the page it then
// asserts on. The digit falls through to Navigate mode's printable-key path,
// is typed into the composer, and the journey's wait times out — a harness
// failure that reads exactly like a product regression.
//
// `workbench_page_keybindings` binds a digit only for the pages in the
// `WorkbenchPage` const it enumerates (`INVESTIGATION`: Map, Scan, Review).
// Prove and Fix are explicit compatibility readers with no digit, so a
// journey reaches them through their phase verbs. This check derives the
// bound digits from those two Rust sources and fails when a journey sends a
// bare digit and then waits for a page that digit cannot reach.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PAGE_SOURCE = "crates/kuzushi-tui/src/app/view_state/sast_task_row.rs";
const KEYMAP_SOURCE = "crates/kuzushi-tui/src/app/state_transitions/view_keybinding_groups.rs";
const JOURNEY_DIR = "scripts/devex/journeys";

// Directives that hand the shell new input. Any of them ends the window in
// which a preceding digit could still be the key that changed the page.
const INPUT_DIRECTIVES = new Set([
  "keys",
  "launch",
  "launch-raw",
  "nav-mode",
  "paste-file",
  "phase-result",
  "shell",
  "submit",
  "type",
]);

// Directives whose value carries screen text the harness matches against the
// rendered frame. `snap`/`live-snap` only name an artifact, so they carry none.
const SCREEN_DIRECTIVES = new Set([
  "expect",
  "expect-wide",
  "require-live-snap",
  "wait-for",
  "wait-live-snap",
  "wait-snap",
]);

/** The digit each `WorkbenchPage` claims, read from `page_key`'s match arms. */
export function pageKeyDigits(pageSource) {
  const block = matchBlock(
    pageSource,
    /fn page_key\(self\) -> char \{\s*match self \{([\s\S]*?)\n\s*\}/,
  );
  const digits = new Map();
  for (const [, page, digit] of block.matchAll(/Self::(\w+) => '(\d)'/g)) {
    digits.set(page, digit);
  }
  if (digits.size === 0) {
    throw new Error(`${PAGE_SOURCE}: page_key declares no digit arms`);
  }
  return digits;
}

/** The `WorkbenchPage` const the Workbench digit bindings enumerate. */
export function digitBoundPageConst(keymapSource) {
  const block = matchBlock(keymapSource, /fn workbench_page_keybindings\(\)[\s\S]*?\n\}/);
  const enumerated = block.match(/WorkbenchPage::([A-Z_]+)\s*\n?\s*\.iter\(\)/);
  if (!enumerated) {
    throw new Error(
      `${KEYMAP_SOURCE}: workbench_page_keybindings no longer enumerates a WorkbenchPage const; teach scripts/check-devex-journey-keys.mjs about its new shape`,
    );
  }
  return enumerated[1];
}

/** The pages listed by a `WorkbenchPage` const such as `INVESTIGATION`. */
export function pageListConst(pageSource, constName) {
  const declaration = matchBlock(
    pageSource,
    new RegExp(`const ${constName}: \\[Self; \\d+\\] = \\[([^\\]]*)\\]`),
  );
  const pages = [...declaration.matchAll(/Self::(\w+)/g)].map(([, page]) => page);
  if (pages.length === 0) {
    throw new Error(`${PAGE_SOURCE}: ${constName} lists no pages`);
  }
  return pages;
}

/** Page name to digit for the pages a Workbench digit actually reaches. */
export function boundPageDigits({ pageSource, keymapSource }) {
  const digits = pageKeyDigits(pageSource);
  const bound = new Map();
  for (const page of pageListConst(pageSource, digitBoundPageConst(keymapSource))) {
    const digit = digits.get(page);
    if (!digit) throw new Error(`${PAGE_SOURCE}: page_key declares no digit for ${page}`);
    bound.set(page, digit);
  }
  return bound;
}

export function journeyDirectives(text) {
  return text.split("\n").flatMap((line, index) => {
    if (line === "" || line.startsWith("#") || !line.includes(":")) return [];
    const directive = line.slice(0, line.indexOf(":"));
    return [{ line: index + 1, directive, value: line.slice(directive.length + 1).trim() }];
  });
}

/**
 * The Workbench page the harness is waiting for, named the two ways the shell
 * renders it. Screen matching is case-insensitive, and text naming more than
 * one page cannot be attributed to a single key.
 */
export function pageNamedByScreenText(value, pageNames) {
  const haystack = value.toLowerCase();
  const named = pageNames.filter((page) => {
    const name = page.toLowerCase();
    return haystack.includes(`viewing ${name}`) || haystack.includes(`${name} is locked`);
  });
  return named.length === 1 ? named[0] : undefined;
}

function pageDigitKey(directive, value) {
  return directive === "keys" && /^[0-9]$/.test(value) ? value : undefined;
}

export function journeyPageKeyViolations({ journey, text, bound, pageNames }) {
  const violations = [];
  let pending;
  for (const { line, directive, value } of journeyDirectives(text)) {
    const digit = pageDigitKey(directive, value);
    if (digit) {
      pending = { line, digit };
    } else if (INPUT_DIRECTIVES.has(directive)) {
      pending = undefined;
    } else if (pending && SCREEN_DIRECTIVES.has(directive)) {
      const page = pageNamedByScreenText(value, pageNames);
      if (page) {
        violations.push(...reachabilityViolation({ journey, pending, page, bound, line }));
        pending = undefined;
      }
    }
  }
  return violations;
}

function reachabilityViolation({ journey, pending, page, bound, line }) {
  const expected = bound.get(page);
  if (expected === pending.digit) return [];
  return [{ journey, line: pending.line, digit: pending.digit, page, expected, waitLine: line }];
}

function matchBlock(source, expression) {
  const found = source.match(expression);
  if (!found) {
    throw new Error(
      `could not read ${expression} from the Rust source; teach scripts/check-devex-journey-keys.mjs about its new shape`,
    );
  }
  return found[1] ?? found[0];
}

function main() {
  const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
  const read = (file) => readFileSync(path.join(root, file), "utf8");
  const pageSource = read(PAGE_SOURCE);
  const bound = boundPageDigits({ pageSource, keymapSource: read(KEYMAP_SOURCE) });
  const pageNames = [...pageKeyDigits(pageSource).keys()];
  const journeys = readdirSync(path.join(root, JOURNEY_DIR))
    .filter((entry) => entry.endsWith(".journey"))
    .sort();
  const violations = journeys.flatMap((journey) =>
    journeyPageKeyViolations({
      journey,
      text: read(path.join(JOURNEY_DIR, journey)),
      bound,
      pageNames,
    }),
  );
  if (violations.length > 0) {
    reportViolations(violations, bound);
    process.exit(1);
  }
  const advertised = [...bound].map(([page, digit]) => `${digit}=${page}`).join(" ");
  console.log(
    `DevEx journey page-key check passed for ${journeys.length} journey(s) (${advertised})`,
  );
}

function reportViolations(violations, bound) {
  console.error("DevEx journey page-key check failed:");
  for (const { journey, line, digit, page, expected, waitLine } of violations) {
    const reach = expected
      ? `${page} is reached with "${expected}"`
      : `the Workbench binds no digit for ${page} — use its phase verb (for example "submit: ${page.toLowerCase()}")`;
    console.error(
      `- ${JOURNEY_DIR}/${journey}:${line} sends "keys: ${digit}" and line ${waitLine} then waits for ${page}; ${reach}`,
    );
  }
  console.error(
    `Workbench digit bindings: ${[...bound].map(([page, digit]) => `${digit}=${page}`).join(" ")}`,
  );
}

const invokedDirectly = process.argv[1]
  ? fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
  : false;
if (invokedDirectly) main();
