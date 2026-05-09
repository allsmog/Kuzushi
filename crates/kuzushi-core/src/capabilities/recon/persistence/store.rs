use super::*;

pub struct ReconWorkspaceStore {
    pub(crate) conn: Connection,
    pub(crate) db_path: String,
}
