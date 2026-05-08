use anyhow::{Context, Result};
use std::path::PathBuf;

pub(crate) const KUZUSHI_DIR: &str = ".kuzushi";
pub(crate) const INDEX_DIR: &str = "index";

pub fn index_root() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not resolve home directory")?;
    let root = home.join(KUZUSHI_DIR).join(INDEX_DIR);
    std::fs::create_dir_all(&root).context("could not create kuzushi index dir")?;
    Ok(root)
}

pub fn manifest_path() -> Result<PathBuf> {
    Ok(index_root()?.join("manifest.json"))
}
