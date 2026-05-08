use super::prelude::*;
use super::*;

impl CacheManifest {
    pub fn load() -> Result<Self> {
        let path = manifest_path()?;
        load_manifest_path(&path)
    }

    pub fn save(&self) -> Result<()> {
        let path = manifest_path()?;
        self.save_to_path(&path)
    }

    pub(crate) fn save_to_path(&self, path: &Path) -> Result<()> {
        let raw = serde_json::to_string_pretty(self).context("could not encode manifest")?;
        write_manifest_path(path, raw)
    }
}

pub(crate) fn load_manifest_path(path: &Path) -> Result<CacheManifest> {
    if !path.exists() {
        return Ok(CacheManifest::default());
    }
    read_manifest_path(path)
}

pub(crate) fn read_manifest_path(path: &Path) -> Result<CacheManifest> {
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("could not read manifest at {}", path.display()))?;
    Ok(serde_json::from_str(&raw).unwrap_or_default())
}

pub(crate) fn write_manifest_path(path: &Path, raw: String) -> Result<()> {
    std::fs::write(path, raw)
        .with_context(|| format!("could not write manifest to {}", path.display()))?;
    Ok(())
}
