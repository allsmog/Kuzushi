use super::prelude::*;
use super::*;

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
    let path = repo.join("compile_commands.json");
    let entries = count_entries(&path).await.unwrap_or(0);
    Ok(CompileDb {
        path,
        generator: Generator::Bear,
        entries,
    })
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
    let path = repo.join("compile_commands.json");
    let entries = count_entries(&path).await.unwrap_or(0);
    Ok(CompileDb {
        path,
        generator: Generator::InterceptBuild,
        entries,
    })
}

pub(crate) async fn count_entries(path: &Path) -> Result<usize> {
    let raw = tokio::fs::read_to_string(path).await?;
    let arr: Vec<serde_json::Value> = serde_json::from_str(&raw)?;
    Ok(arr.len())
}
