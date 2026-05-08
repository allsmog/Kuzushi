use super::prelude::*;
use super::*;

mod prelude;
pub(in crate::modules) use prelude::*;
mod siblings;
pub(in crate::modules) use siblings::*;
mod dispatch_plugin_prompt_tool;
mod items_1;
mod items_2;
mod items_3;
#[cfg(test)]
mod tests;
mod with_v2_builtins;
pub use items_1::ModuleRegistry;
