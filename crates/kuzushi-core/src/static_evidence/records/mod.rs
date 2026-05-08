use super::*;

mod edge_rows;
mod ids;
mod node_rows;
mod validation;

pub(crate) use edge_rows::row_to_edge;
pub(crate) use ids::evidence_node_id;
pub(crate) use node_rows::row_to_node;
pub(crate) use validation::{validate_edge, validate_node};

fn optional_u32(value: Option<i64>, name: &'static str) -> rusqlite::Result<Option<u32>> {
    match value {
        Some(value) if value < 0 || value > i64::from(u32::MAX) => Err(to_sql_anyhow_error(
            anyhow::anyhow!("static evidence {name} value {value} is out of range"),
        )),
        Some(value) => Ok(Some(value as u32)),
        None => Ok(None),
    }
}
