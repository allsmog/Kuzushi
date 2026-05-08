use super::prelude::*;
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompileDb {
    pub path: PathBuf,
    pub generator: Generator,
    pub entries: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Generator {
    PreExisting,
    Cmake,
    Bear,
    InterceptBuild,
    None,
}

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

pub(crate) async fn generate_with_cmake(repo: &Path) -> Result<CompileDb> {
    let build_dir = repo.join("build");
    ensure_cmake_build_dir(&build_dir).await?;
    run_cmake_configure(&build_dir).await?;
    cmake_compile_db(build_dir).await
}

pub(crate) async fn ensure_cmake_build_dir(build_dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(&build_dir).await?;
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
