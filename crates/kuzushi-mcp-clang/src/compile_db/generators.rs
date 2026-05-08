use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::process::Command;

use super::{CompileDb, Generator};

pub(crate) async fn generate_with_cmake(repo: &Path) -> Result<CompileDb> {
    let build_dir = repo.join("build");
    ensure_cmake_build_dir(&build_dir).await?;
    run_cmake_configure(&build_dir).await?;
    cmake_compile_db(build_dir).await
}

pub(crate) async fn ensure_cmake_build_dir(build_dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(build_dir).await?;
    Ok(())
}

pub(crate) async fn run_cmake_configure(build_dir: &Path) -> Result<()> {
    let status = Command::new("cmake")
        .arg("-DCMAKE_EXPORT_COMPILE_COMMANDS=ON")
        .arg("..")
        .current_dir(build_dir)
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("cmake configure failed: exit {}", status);
    }
    Ok(())
}

pub(crate) async fn cmake_compile_db(build_dir: PathBuf) -> Result<CompileDb> {
    let path = build_dir.join("compile_commands.json");
    let entries = count_entries(&path).await.unwrap_or(0);
    Ok(CompileDb {
        path,
        generator: Generator::Cmake,
        entries,
    })
}

pub(crate) async fn generate_with_bear(repo: &Path) -> Result<CompileDb> {
    let status = Command::new("bear")
        .arg("--")
        .arg("make")
        .current_dir(repo)
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("bear make failed: exit {}", status);
    }
    generated_compile_db(repo, Generator::Bear).await
}

pub(crate) async fn generate_with_intercept_build(repo: &Path) -> Result<CompileDb> {
    let status = Command::new("intercept-build")
        .arg("make")
        .current_dir(repo)
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("intercept-build make failed: exit {}", status);
    }
    generated_compile_db(repo, Generator::InterceptBuild).await
}

async fn generated_compile_db(repo: &Path, generator: Generator) -> Result<CompileDb> {
    let path = repo.join("compile_commands.json");
    let entries = count_entries(&path).await.unwrap_or(0);
    Ok(CompileDb {
        path,
        generator,
        entries,
    })
}

pub(crate) async fn count_entries(path: &Path) -> Result<usize> {
    let raw = tokio::fs::read_to_string(path).await?;
    let arr: Vec<serde_json::Value> = serde_json::from_str(&raw)?;
    Ok(arr.len())
}
