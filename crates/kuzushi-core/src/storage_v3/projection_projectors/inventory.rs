use super::super::projection_payload::{
    payload_i64, payload_str, require_payload_i64, require_payload_str,
};
use super::super::sql_seq;
use crate::event_log::{EventEnvelope, EventKind};
use anyhow::Result;
use rusqlite::{params, Transaction};

pub(super) fn project_snapshot_indexed(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<()> {
    if event.event_kind != EventKind::SnapshotIndexed {
        return Ok(());
    }
    tx.execute(
        r#"
        insert into target_snapshots(
          snapshot_hash, tree_hash, workspace_root_fingerprint, git_commit,
          git_branch, dirty_hash, index_hash, config_hash, created_at
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        on conflict(snapshot_hash) do update set
          tree_hash = excluded.tree_hash,
          workspace_root_fingerprint = excluded.workspace_root_fingerprint,
          git_commit = excluded.git_commit,
          git_branch = excluded.git_branch,
          dirty_hash = excluded.dirty_hash,
          index_hash = excluded.index_hash,
          config_hash = excluded.config_hash,
          created_at = excluded.created_at
        "#,
        params![
            require_payload_str(&event.payload, "snapshotHash")?,
            require_payload_str(&event.payload, "treeHash")?,
            require_payload_str(&event.payload, "workspaceRootFingerprint")?,
            payload_str(&event.payload, "gitCommit"),
            payload_str(&event.payload, "gitBranch"),
            payload_str(&event.payload, "dirtyHash"),
            payload_str(&event.payload, "indexHash"),
            payload_str(&event.payload, "configHash"),
            event.created_at,
        ],
    )?;
    Ok(())
}

pub(super) fn project_file_indexed(tx: &Transaction<'_>, event: &EventEnvelope) -> Result<()> {
    if event.event_kind != EventKind::FileIndexed {
        return Ok(());
    }
    project_indexed_blob(tx, event)?;
    tx.execute(
        r#"
        insert into indexed_files(
          snapshot_hash, path, blob_hash, file_size, mtime_ns,
          git_blob_oid, language, ast_hash, indexed_at
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        on conflict(snapshot_hash, path) do update set
          blob_hash = excluded.blob_hash,
          file_size = excluded.file_size,
          mtime_ns = excluded.mtime_ns,
          git_blob_oid = excluded.git_blob_oid,
          language = excluded.language,
          ast_hash = excluded.ast_hash,
          indexed_at = excluded.indexed_at
        "#,
        params![
            require_payload_str(&event.payload, "snapshotHash")?,
            require_payload_str(&event.payload, "path")?,
            require_payload_str(&event.payload, "blobHash")?,
            require_payload_i64(&event.payload, "fileSize")?,
            payload_i64(&event.payload, "mtimeNs"),
            payload_str(&event.payload, "gitBlobOid"),
            payload_str(&event.payload, "language"),
            payload_str(&event.payload, "astHash"),
            event.created_at,
        ],
    )?;
    Ok(())
}

pub(super) fn project_file_deleted(tx: &Transaction<'_>, event: &EventEnvelope) -> Result<()> {
    if event.event_kind != EventKind::FileDeleted {
        return Ok(());
    }
    let snapshot_hash = require_payload_str(&event.payload, "snapshotHash")?;
    let path = require_payload_str(&event.payload, "path")?;
    tx.execute(
        "delete from indexed_files where snapshot_hash = ?1 and path = ?2",
        params![snapshot_hash, path],
    )?;
    tx.execute(
        r#"
        insert into file_deletions(
          event_hash, seq, snapshot_hash, path, actor, created_at
        )
        values (?1, ?2, ?3, ?4, ?5, ?6)
        on conflict(event_hash) do nothing
        "#,
        params![
            event.event_hash.as_str(),
            sql_seq(event.seq)?,
            snapshot_hash,
            path,
            event.actor,
            event.created_at,
        ],
    )?;
    Ok(())
}

pub(super) fn project_attack_surface_indexed(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<()> {
    if event.event_kind != EventKind::AttackSurfaceIndexed {
        return Ok(());
    }
    tx.execute(
        r#"
        insert into attack_surface_snapshots(
          event_hash, seq, snapshot_hash, run_id, object_hash,
          summary, actor, created_at, payload_json
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        on conflict(event_hash) do nothing
        "#,
        params![
            event.event_hash.as_str(),
            sql_seq(event.seq)?,
            require_payload_str(&event.payload, "snapshotHash")?,
            payload_str(&event.payload, "runId"),
            payload_str(&event.payload, "objectHash"),
            require_payload_str(&event.payload, "summary")?,
            event.actor,
            event.created_at,
            event.payload.to_string(),
        ],
    )?;
    Ok(())
}

fn project_indexed_blob(tx: &Transaction<'_>, event: &EventEnvelope) -> Result<()> {
    tx.execute(
        r#"
        insert into blobs(blob_hash, size_bytes, media_type, storage_path)
        values (?1, ?2, ?3, ?4)
        on conflict(blob_hash) do update set
          size_bytes = excluded.size_bytes,
          media_type = excluded.media_type,
          storage_path = excluded.storage_path
        "#,
        params![
            require_payload_str(&event.payload, "blobHash")?,
            require_payload_i64(&event.payload, "fileSize")?,
            payload_str(&event.payload, "mediaType"),
            payload_str(&event.payload, "storagePath").unwrap_or(""),
        ],
    )?;
    Ok(())
}
