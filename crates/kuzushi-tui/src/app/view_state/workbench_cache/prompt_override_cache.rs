use kuzushi_core::prompt_content_sha256;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Default)]
pub(super) struct PromptOverrideCache {
    entries: BTreeMap<PathBuf, PromptOverrideEntry>,
}

impl PromptOverrideCache {
    pub(super) fn hash(&mut self, path: &Path) -> Result<Option<String>, String> {
        let stamp = prompt_override_stamp(path).map_err(|error| error.to_string())?;
        if let Some(cache) = self.entries.get(path).filter(|cache| cache.stamp == stamp) {
            return Ok(cache.hash.clone());
        }
        let hash = prompt_override_hash_for_stamp(path, stamp)?;
        self.entries.insert(
            path.to_path_buf(),
            PromptOverrideEntry {
                stamp,
                hash: hash.clone(),
            },
        );
        Ok(hash)
    }
}

#[derive(Debug)]
struct PromptOverrideEntry {
    stamp: PromptOverrideStamp,
    hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptOverrideStamp {
    Present(FileStamp),
    Missing(Option<FileStamp>),
}

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

fn parent_stamp(path: &Path) -> Option<FileStamp> {
    let parent = path.parent()?;
    std::fs::metadata(parent).ok().map(FileStamp::from_metadata)
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

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
    fn prompt_override_hash_refreshes_when_file_changes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("prompt.md");
        let mut cache = PromptOverrideCache::default();

        assert_eq!(cache.hash(&path).unwrap(), None);
        std::fs::write(&path, "one").unwrap();
        let first = cache.hash(&path).unwrap();
        std::fs::write(&path, "two lines").unwrap();
        let second = cache.hash(&path).unwrap();

        assert_eq!(first, Some(prompt_content_sha256("one")));
        assert_eq!(second, Some(prompt_content_sha256("two lines")));
    }
}
