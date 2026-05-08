use super::prelude::*;
use super::*;

/// Empirical exploit-gated verify: scaffolds a sandboxed test harness from
/// the finding's location and observes whether it crashes. Promotes to
/// `proof_level=4` only on observed crash inside an isolating sandbox.
/// Complementary to (not a replacement for) the LLM-driven `verify:finding`.
mod prelude;
pub(in crate::modules) use prelude::*;
mod siblings;
pub(in crate::modules) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod items_4;
#[cfg(test)]
mod tests;
