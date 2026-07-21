use super::*;

pub(crate) fn row_to_host(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReconHost> {
    Ok(ReconHost {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        address: row.get(2)?,
        hostname: row.get(3)?,
        state: row.get(4)?,
    })
}

pub(crate) fn row_to_service(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReconService> {
    Ok(ReconService {
        id: row.get(0)?,
        host_id: row.get(1)?,
        // Typed get range-checks: a corrupted row surfaces as an error
        // instead of silently truncating into a different port.
        port: row.get(2)?,
        proto: row.get(3)?,
        name: row.get(4)?,
        banner: row.get(5)?,
        state: row.get(6)?,
    })
}

pub(crate) fn row_to_note(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReconNote> {
    let data_raw: String = row.get(5)?;
    Ok(ReconNote {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        host_id: row.get(2)?,
        service_id: row.get(3)?,
        ntype: row.get(4)?,
        data: serde_json::from_str(&data_raw).unwrap_or(Value::Null),
    })
}
