mod protocol;
mod spawn;
#[cfg(test)]
mod tests;
mod types;

pub use types::{ClientError, McpClient};

pub(crate) use protocol::*;
