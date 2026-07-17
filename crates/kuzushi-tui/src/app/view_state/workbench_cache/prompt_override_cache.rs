#[cfg(test)]
use kuzushi_core::prompt_content_sha256;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::time::SystemTime;

#[derive(Debug, Default)]
pub(super) struct PromptOverrideCache {
    entries: BTreeMap<PathBuf, PromptOverrideEntry>,
}

impl PromptOverrideCache {
    pub(super) fn cached(&self, path: &Path) -> Option<Result<Option<String>, String>> {
        self.entries.get(path).map(|entry| entry.state.clone())
    }

    pub(super) fn store(&mut self, path: PathBuf, state: Result<Option<String>, String>) {
        self.entries.insert(path, PromptOverrideEntry { state });
    }

    #[cfg(test)]
    pub(super) fn hash(&mut self, path: &Path) -> Result<Option<String>, String> {
        if let Some(cache) = self.entries.get(path) {
            return cache.state.clone();
        }
        let stamp = prompt_override_stamp(path).map_err(|error| error.to_string())?;
        let hash = prompt_override_hash_for_stamp(path, stamp)?;
        self.store(path.to_path_buf(), Ok(hash.clone()));
        Ok(hash)
    }

    pub(super) fn invalidate(&mut self) {
        self.entries.clear();
    }
}

#[derive(Debug)]
struct PromptOverrideEntry {
    state: Result<Option<String>, String>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptOverrideStamp {
    Present(FileStamp),
    Missing(Option<FileStamp>),
}

#[cfg(test)]
fn prompt_override_stamp(path: &Path) -> std::io::Result<PromptOverrideStamp> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(PromptOverrideStamp::Present(FileStamp::from_metadata(
            metadata,
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(PromptOverrideStamp::Missing(parent_stamp(path)))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
fn parent_stamp(path: &Path) -> Option<FileStamp> {
    let parent = path.parent()?;
    std::fs::metadata(parent).ok().map(FileStamp::from_metadata)
}

#[cfg(test)]
fn prompt_override_hash_for_stamp(
    path: &Path,
    stamp: PromptOverrideStamp,
) -> Result<Option<String>, String> {
    match stamp {
        PromptOverrideStamp::Present(_) => {
            let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
            Ok(Some(prompt_content_sha256(&text)))
        }
        PromptOverrideStamp::Missing(_) => Ok(None),
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

#[cfg(test)]
impl FileStamp {
    fn from_metadata(metadata: std::fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_override_hash_refreshes_after_workspace_invalidation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("prompt.md");
        let mut cache = PromptOverrideCache::default();

        assert_eq!(cache.hash(&path).unwrap(), None);
        std::fs::write(&path, "one").unwrap();
        cache.invalidate();
        let first = cache.hash(&path).unwrap();
        std::fs::write(&path, "two lines").unwrap();
        cache.invalidate();
        let second = cache.hash(&path).unwrap();

        assert_eq!(first, Some(prompt_content_sha256("one")));
        assert_eq!(second, Some(prompt_content_sha256("two lines")));
    }
}
