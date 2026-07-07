mod open;
mod rows;
mod store;

pub use store::ReconWorkspaceStore;

use crate::capabilities::recon::domain::{now_isoish, ReconHost, ReconNote, ReconService};
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use rows::{row_to_host, row_to_note, row_to_service};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::path::Path;
use uuid::Uuid;
