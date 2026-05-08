use anyhow::Result;
use kuzushi_mcp_common::doctor::which;
use std::path::{Path, PathBuf};

use super::generators::{
    count_entries, generate_with_bear, generate_with_cmake, generate_with_intercept_build,
};
use super::{CompileDb, Generator};

pub async fn resolve(repo: &Path) -> Result<CompileDb> {
    if let Some(path) = find_existing(repo) {
        let entries = count_entries(&path).await.unwrap_or(0);
        return Ok(CompileDb {
            path,
            generator: Generator::PreExisting,
            entries,
        });
    }

    if which("cmake").is_some() && repo.join("CMakeLists.txt").exists() {
        if let Ok(db) = generate_with_cmake(repo).await {
            return Ok(db);
        }
    }

    if which("bear").is_some() && repo.join("Makefile").exists() {
        if let Ok(db) = generate_with_bear(repo).await {
            return Ok(db);
        }
    }

    if which("intercept-build").is_some() && repo.join("Makefile").exists() {
        if let Ok(db) = generate_with_intercept_build(repo).await {
            return Ok(db);
        }
    }

    Ok(CompileDb {
        path: repo.to_path_buf(),
        generator: Generator::None,
        entries: 0,
    })
}

pub(crate) fn find_existing(repo: &Path) -> Option<PathBuf> {
    let candidates = [
        repo.join("compile_commands.json"),
        repo.join("build").join("compile_commands.json"),
        repo.join(".vscode").join("compile_commands.json"),
    ];
    candidates.into_iter().find(|p| p.exists())
}
