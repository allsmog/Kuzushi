// kuzushi-eval — recall scorer for the xint-eval harness.
//
// Reads an oracle JSON (ground-truth bug locations) and a findings JSON dump
// (`kuzushi findings --target … --json`), and emits a match report under four
// tolerance modes simultaneously: exact_line, pm_lines, function, file_only.
//
// Phase 0 ships without tree-sitter, so the `function` tolerance falls back to
// pm_lines:50. Phase 5 will rewire it to the real enclosing-function lookup.

mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod items_4;
mod items_5;
mod items_6;
#[cfg(test)]
mod tests;

fn main() -> anyhow::Result<()> {
    items_2::main()
}
