import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  boundPageDigits,
  digitBoundPageConst,
  journeyDirectives,
  journeyPageKeyViolations,
  pageKeyDigits,
  pageListConst,
  pageNamedByScreenText,
} from "./check-devex-journey-keys.mjs";

const PAGE_SOURCE = `
    pub const ALL: [Self; 5] = [Self::Map, Self::Scan, Self::Review, Self::Prove, Self::Fix];

    pub const INVESTIGATION: [Self; 3] = [Self::Map, Self::Scan, Self::Review];

    pub const fn page_key(self) -> char {
        match self {
            Self::Map => '1',
            Self::Scan => '2',
            Self::Review => '3',
            Self::Prove => '4',
            Self::Fix => '5',
        }
    }
`;

const KEYMAP_SOURCE = `
fn workbench_page_keybindings() -> Vec<ViewKeybinding> {
    let mut bindings: Vec<_> = WorkbenchPage::INVESTIGATION
        .iter()
        .map(|page| bind_char(page.page_key(), "1..3", "page", ViewHotkeyAction::WorkbenchPage(*page)))
        .collect();
    bindings
}
`;

const SOURCES = { pageSource: PAGE_SOURCE, keymapSource: KEYMAP_SOURCE };
const PAGE_NAMES = ["Map", "Scan", "Review", "Prove", "Fix"];

function violations(text) {
  return journeyPageKeyViolations({
    journey: "fixture.journey",
    text,
    bound: boundPageDigits(SOURCES),
    pageNames: PAGE_NAMES,
  });
}

test("the bound digits are the page_key arms the Workbench keymap enumerates", () => {
  assert.equal(digitBoundPageConst(KEYMAP_SOURCE), "INVESTIGATION");
  assert.deepEqual(pageListConst(PAGE_SOURCE, "INVESTIGATION"), ["Map", "Scan", "Review"]);
  assert.equal(pageKeyDigits(PAGE_SOURCE).get("Prove"), "4");
  assert.deepEqual(
    [...boundPageDigits(SOURCES)],
    [
      ["Map", "1"],
      ["Scan", "2"],
      ["Review", "3"],
    ],
  );
});

test("a keymap that stops enumerating a page const fails loudly", () => {
  assert.throws(
    () => digitBoundPageConst("fn workbench_page_keybindings() -> Vec<ViewKeybinding> {\n}\n"),
    /no longer enumerates a WorkbenchPage const/,
  );
});

test("comments and blank lines are not directives", () => {
  assert.deepEqual(journeyDirectives("# keys: 4\n\nkeys: 4\nnot a directive"), [
    { line: 3, directive: "keys", value: "4" },
  ]);
});

test("screen text naming one page is attributed, ambiguous text is not", () => {
  assert.equal(pageNamedByScreenText("15 Viewing Prove | prove-initial", PAGE_NAMES), "Prove");
  assert.equal(pageNamedByScreenText("15 Prove is locked | p", PAGE_NAMES), "Prove");
  assert.equal(pageNamedByScreenText("30 Viewing Review || Viewing Prove", PAGE_NAMES), undefined);
  assert.equal(pageNamedByScreenText("10 MAP · MODULES", PAGE_NAMES), undefined);
});

test("a digit the Workbench never binds is reported with the page it cannot reach", () => {
  const found = violations("nav-mode:\nkeys: 4\nwait-live-snap: 10 Viewing Prove | prove\n");
  assert.deepEqual(found, [
    {
      journey: "fixture.journey",
      line: 2,
      digit: "4",
      page: "Prove",
      expected: undefined,
      waitLine: 3,
    },
  ]);
});

test("a digit that reaches a different page than the journey waits for is reported", () => {
  const found = violations("keys: 1\nwait-live-snap: 10 Viewing Scan | scan\n");
  assert.equal(found.length, 1);
  assert.equal(found[0].expected, "2");
});

test("the digit a page is bound to passes", () => {
  assert.deepEqual(violations("keys: 3\nwait-live-snap: 15 Viewing Review | review\n"), []);
});

// The MAP · MODULES planner selects rows by index, so `keys: 4` there is not
// page navigation. A later input directive ends the window in which the digit
// could still be what changed the page.
test("a picker digit followed by another input directive is left alone", () => {
  const picker = [
    "keys: 4",
    "wait: 1",
    "keys: Enter",
    "wait-live-snap: 10 Viewing Prove | prove",
    "",
  ].join("\n");
  assert.deepEqual(violations(picker), []);
});

// A page assertion can sit several lines after the wait that reached it, so a
// screen read naming no page must not end the window either.
test("a page named only by a later expect is still attributed to the digit", () => {
  const delayed = [
    "keys: 5",
    "wait-live-snap: 15 Staged for approval | fix",
    "expect: Viewing Fix",
    "",
  ].join("\n");
  assert.equal(violations(delayed).length, 1);
});

test("every shipped journey satisfies the check against the real Rust sources", () => {
  const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
  const read = (file) => readFileSync(path.join(root, file), "utf8");
  const pageSource = read("crates/kuzushi-tui/src/app/view_state/sast_task_row.rs");
  const bound = boundPageDigits({
    pageSource,
    keymapSource: read("crates/kuzushi-tui/src/app/state_transitions/view_keybinding_groups.rs"),
  });
  assert.deepEqual([...bound.keys()], ["Map", "Scan", "Review"]);
  assert.equal([...pageKeyDigits(pageSource).keys()].length, 5);
});
