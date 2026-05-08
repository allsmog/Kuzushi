use super::prelude::*;
use super::*;

#[derive(Default)]
pub struct IndexFacade {
    pub gtags: Option<McpClient>,
    pub clang: Option<McpClient>,
    pub joern: Option<McpClient>,
    pub(crate) routing: RoutingTable,
}
