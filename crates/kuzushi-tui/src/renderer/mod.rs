pub(in crate::renderer) use super::prelude::*;
pub(in crate::renderer) use super::*;

mod prelude;
pub(in crate::renderer) use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod chrome;
mod plain;
mod shared;
mod views;

mod items_1;
mod items_2;
#[cfg(test)]
mod tests;
pub use items_1::render_app;
pub use plain::{render_plain_app, render_plain_command_result};
