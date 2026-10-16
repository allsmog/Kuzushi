# Phase-page navigation keys in the DevEx journeys

## What was wrong

Eight journeys reached the durable Prove and Fix pages by sending the bare
digits `4` and `5`. The Workbench stopped binding those digits when
`workbench_page_keybindings` narrowed to `WorkbenchPage::INVESTIGATION`
(Map, Scan, Review). An unbound plain character in Navigate mode is claimed by
`type_printable_navigate_key`, so the digit was typed into the composer, the
page never changed, and the journey's wait timed out fifteen seconds later with
a snapshot of the composer holding a stray digit.

Thirteen steps across J17, J21, J24, J25, J31, J32, J33 and J39 were affected.
The #172 audit thread reported the J25 pair on 2026-10-05 and reconfirmed it on
10-10, 10-11 and 10-12; nothing in CI or `pnpm verify:quick` runs or lints the
journeys, so the drift survived every run.

Reproduced on this head before the change: `J17` reported 20 failures, 15 of
them the two timeouts and the thirteen `expect` steps left with no snapshot.

## What changed

Those thirteen steps now submit the documented phase verbs (`prove`, `fix`)
instead of a digit the shell never bound, and the `nav-mode:` step that existed
only to make the digit land in Navigate moved to wherever a raw Navigate key
still follows a submitted command.

`scripts/check-devex-journey-keys.mjs` keeps the harness and the keymap one
fact. It derives the digit-bound pages from `page_key`'s match arms intersected
with the `WorkbenchPage` const `workbench_page_keybindings` enumerates, then
fails any journey that sends a bare digit and afterwards waits for a page that
digit cannot reach. It runs in `pnpm quality:architecture`, so it is in both the
quick and CI verification plans.

## What is still open — owner decision

The verbs do not restore the coverage, and J17 still fails the same fifteen
assertions. `prove` and `fix` open the durable page only when
`phase_verb_opens_page` is true, which needs the phase complete, passed, or
holding an unresolved attempt
(`crates/kuzushi-tui/src/ui_view_models/journey.rs:802`). The reference fixture
models an engagement resting at Review (`devex_phase_fixture::mod.rs`
`commit_reference_engagement`: "has already completed Map and Scan"), so both
verbs open their planner instead — observed live as
`planning PROVE · engagement is in Review`.

No other route reaches those pages from that state. `investigation_neighbor`
returns `None` forward of Review, so Tab and Shift+Tab reach Report rather than
Prove; `Esc` from a planner restores the previous view; no keybinding group
binds `ViewHotkeyAction::WorkbenchPage(Prove | Fix)`; and no hint row advertises
one. Only an operator-authored runtime keymap, which can name the `prove` and
`fix` actions (`app/runtime_keymap/parsing.rs`), still opens them.

That leaves the documented contract inconsistent with itself: `plan <phase>` is
described as "always the planner" against a bare verb that opens the page, but
while the phase is unreached both do the same thing and the compatibility
reader has no route at all. Two candidate fixes, both owner calls because each
revisits a 2026-10-04 decision or the reference fixture's meaning:

1. Give the reference fixture durable Prove and Fix attempts so the verbs open
   the pages. This restores every assertion unweakened, but it changes the rail
   and the "6 remaining findings" state the same journeys audit, so the
   currently passing Map, Scan and Review assertions need re-verification.
2. Give the compatibility readers an explicit route again — re-bind the digits
   `page_key` still claims for them, or make the bare verb open the page and
   leave `plan <phase>` as the only planner.

Until one lands, these journeys fail legibly: the captured screen is the
planner naming the engagement's real phase, not a composer with a stray digit.

`page_key` is a related latent trap. Its doc comment promises "the digit that
reaches this page in the Workbench keymap", and it still answers `'4'` and
`'5'` for Prove and Fix. No hint lies today only because every caller asks for
`Review`. The new check reads both sources, so a hint that starts advertising
an unbound digit is caught by a journey, not by an operator.

| Verification | Result |
| --- | --- |
| `pnpm verify:quick:summary` | All ten steps status 0 |
| `node --test scripts/check-devex-journey-keys.test.mjs` | 10 passed |
| `node scripts/check-devex-journey-keys.mjs` | Passed for 281 journeys (1=Map 2=Scan 3=Review) |
| Native `J17` before and after | 20 failures both times; the two phase waits now capture the planner instead of the composer |
| `git diff --check` | Clean |

Journey evidence is retained under
`/tmp/kuzushi-phase-page-keys-20261016`.
