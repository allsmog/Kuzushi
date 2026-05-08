use super::prelude::*;
use super::*;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepoFingerprint {
    pub canonical_path: PathBuf,
    pub git_remote: Option<String>,
    pub hash: String,
}

pub fn repo_hash(path: &Path) -> Result<RepoFingerprint> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("could not canonicalize {}", path.display()))?;
    let git_remote = read_git_remote(&canonical);

    let mut input = canonical.display().to_string();
    if let Some(remote) = &git_remote {
        input.push('|');
        input.push_str(remote);
    }
    let hash = sha256_hex(&input);

    Ok(RepoFingerprint {
        canonical_path: canonical,
        git_remote,
        hash,
    })
}

pub(crate) fn read_git_remote(repo: &Path) -> Option<String> {
    let head_config = repo.join(".git").join("config");
    if !head_config.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&head_config).ok()?;
    // Cheap parse: look for a [remote "origin"] block and the next `url = ...`.
    let mut in_origin = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_origin = trimmed == "[remote \"origin\"]";
            continue;
        }
        if in_origin {
            if let Some(rest) = trimmed.strip_prefix("url") {
                let value = rest.trim_start_matches([' ', '=']).trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

pub(crate) fn sha256_hex(input: &str) -> String {
    let bytes = sha256_bytes(input.as_bytes());
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
