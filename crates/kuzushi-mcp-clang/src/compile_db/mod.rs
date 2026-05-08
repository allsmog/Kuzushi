use super::prelude::*;
use super::*;

mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod prelude;
/// Locate or generate `compile_commands.json` for `repo`.

#[cfg(test)]
mod tests;
pub use items_1::resolve;
pub use items_1::CompileDb;
pub use items_1::Generator;
