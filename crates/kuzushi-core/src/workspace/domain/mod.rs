use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

mod program_scope;
mod workspace_target;

pub use program_scope::{
    HostPattern, ProgramScope, ProgramScopeFile, ProgramScopeList, ScopeVerdict,
};
pub use workspace_target::{WorkspaceExportFormat, WorkspaceFindingsExport, WorkspaceTarget};
