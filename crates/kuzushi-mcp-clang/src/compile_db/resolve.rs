use anyhow::{Context, Result};
use kuzushi_mcp_common::{AuthorizedDirectory, BoundedReadFile};
use std::path::{Path, PathBuf};

use super::{CompileDb, Generator};

const MAX_COMPILE_DATABASE_BYTES: usize = 8 * 1024 * 1024;
const COMPILE_DATABASE_CANDIDATES: &[&str] = &[
    "compile_commands.json",
    "build/compile_commands.json",
    ".vscode/compile_commands.json",
];

pub async fn resolve(repo: &AuthorizedDirectory) -> Result<CompileDb> {
    if let Some(database) = find_existing(repo)? {
        return compile_db(database, Generator::PreExisting);
    }
    Ok(no_compile_db(repo))
}

fn no_compile_db(repo: &AuthorizedDirectory) -> CompileDb {
    CompileDb {
        path: repo.path().to_path_buf(),
        generator: Generator::None,
        entries: 0,
    }
}

pub(crate) fn find_existing(repo: &AuthorizedDirectory) -> Result<Option<BoundedReadFile>> {
    for candidate in COMPILE_DATABASE_CANDIDATES {
        match repo.open_file(Path::new(candidate), MAX_COMPILE_DATABASE_BYTES) {
            Ok(file) => return Ok(Some(file)),
            Err(_error) if path_is_missing(repo.path().join(candidate)) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

fn path_is_missing(path: PathBuf) -> bool {
    std::fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn compile_db(file: BoundedReadFile, generator: Generator) -> Result<CompileDb> {
    let path = file.path().to_path_buf();
    let entries = count_entries(file)?;
    Ok(CompileDb {
        path,
        generator,
        entries,
    })
}

pub(crate) fn count_entries(file: BoundedReadFile) -> Result<usize> {
    let raw = file.read_utf8()?;
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&raw).context("compile_commands.json is malformed")?;
    Ok(entries.len())
}
