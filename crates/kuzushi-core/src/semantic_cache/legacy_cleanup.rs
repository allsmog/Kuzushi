//! Legacy entries are safe misses. Cleanup checkpoints only completed shards;
//! an interrupted shard is retried immediately, with bounded work on every open.
use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

pub(super) fn prune_batch(root: &Path, connection: &Connection) -> Result<(u64, bool)> {
    let mut shard: u32 = connection.query_row(
        "SELECT legacy_shard FROM cache_state WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    let mut remaining = 64;
    let mut reclaimed = 0;
    while shard < 256 && remaining > 0 {
        remaining -= 1;
        let (bytes, complete) = prune_shard(&root.join(format!("{shard:02x}")), &mut remaining)?;
        reclaimed += bytes;
        if !complete {
            break;
        }
        shard += 1;
    }
    connection.execute("UPDATE cache_state SET legacy_shard=?1 WHERE id=1", [shard])?;
    Ok((reclaimed, shard < 256))
}

fn prune_shard(path: &Path, remaining: &mut usize) -> Result<(u64, bool)> {
    let directory = match std::fs::read_dir(path) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((0, true)),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        std::fs::symlink_metadata(path)?.is_dir(),
        "legacy shard must be a directory"
    );
    let mut reclaimed = 0;
    for entry in directory {
        if *remaining == 0 {
            return Ok((reclaimed, false));
        }
        *remaining -= 1;
        reclaimed += remove_entry(&entry?.path())?;
    }
    std::fs::remove_dir(path)?;
    Ok((reclaimed, true))
}

fn remove_entry(path: &Path) -> Result<u64> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let hash = name.strip_suffix(".json").unwrap_or_default();
    anyhow::ensure!(
        crate::identity::Blake3Hash::new(hash.to_string()).is_ok(),
        "unrecognized file in legacy cache shard"
    );
    let metadata = std::fs::symlink_metadata(path)?;
    std::fs::remove_file(path)?;
    Ok(metadata.len())
}
