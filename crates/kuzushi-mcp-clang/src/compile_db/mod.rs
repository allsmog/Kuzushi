mod model;
mod resolve;

#[cfg(test)]
mod tests;

pub use model::{CompileDb, Generator};
pub use resolve::resolve;

#[cfg(test)]
pub(crate) use resolve::count_entries;
