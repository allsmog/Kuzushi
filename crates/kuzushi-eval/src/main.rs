// kuzushi-eval — recall scorer for the recall-eval harness.
//
// Reads an oracle JSON (ground-truth bug locations) and a findings JSON dump
// (`kuzushi findings --target … --json`), and emits a match report under four
// tolerance modes simultaneously: exact_line, pm_lines, function, file_only.
//
// Phase 0 ships without tree-sitter, so the `function` tolerance falls back to
// pm_lines:50. Phase 5 will rewire it to the real enclosing-function lookup.

mod assignment;
mod breakdowns;
mod cli;
mod input;
mod oracle_matching;
mod path_cwe;
mod report;
mod runner;
mod scoring;
mod tolerance;

pub(crate) use breakdowns::*;
pub(crate) use cli::*;
pub(crate) use input::*;
pub(crate) use oracle_matching::*;
pub(crate) use path_cwe::*;
pub(crate) use report::*;
pub(crate) use scoring::*;
pub(crate) use tolerance::*;

#[cfg(test)]
pub(crate) use runner::{load_match_report, render_match_report};

#[cfg(test)]
mod tests;

fn main() -> anyhow::Result<()> {
    runner::run_cli()
}
