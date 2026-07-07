use crate::identity::Blake3Hash;
use anyhow::Result;
use kuzushi_sandbox::MountSpec;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedSnapshot {
    blobs: BTreeMap<Blake3Hash, GrantedBlob>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedBlob {
    pub size_bytes: u64,
    pub object_path: Option<PathBuf>,
}

impl GrantedSnapshot {
    pub fn new(blobs: BTreeMap<Blake3Hash, u64>) -> Self {
        Self {
            blobs: blobs
                .into_iter()
                .map(|(hash, size_bytes)| {
                    (
                        hash,
                        GrantedBlob {
                            size_bytes,
                            object_path: None,
                        },
                    )
                })
                .collect(),
        }
    }

    pub fn with_objects(blobs: impl IntoIterator<Item = (Blake3Hash, u64, PathBuf)>) -> Self {
        Self {
            blobs: blobs
                .into_iter()
                .map(|(hash, size_bytes, object_path)| {
                    (
                        hash,
                        GrantedBlob {
                            size_bytes,
                            object_path: Some(object_path),
                        },
                    )
                })
                .collect(),
        }
    }

    pub(super) fn blob_size(&self, hash: &Blake3Hash) -> Option<u64> {
        self.blobs.get(hash).map(|blob| blob.size_bytes)
    }

    pub(super) fn object_path(&self, hash: &Blake3Hash) -> Option<&PathBuf> {
        self.blobs
            .get(hash)
            .and_then(|blob| blob.object_path.as_ref())
    }

    pub(super) fn manifest_json(&self, include_paths: bool) -> Result<String> {
        Ok(serde_json::to_string(&PluginInvocationManifest {
            blobs: self.manifest_blobs(include_paths),
        })?)
    }

    pub(super) fn read_only_mounts(&self) -> Vec<MountSpec> {
        self.blobs
            .iter()
            .filter_map(|(hash, blob)| {
                blob.object_path.as_ref().map(|object_path| MountSpec {
                    host_path: object_path.clone(),
                    guest_path: PathBuf::from(guest_blob_path(hash)),
                })
            })
            .collect()
    }

    fn manifest_blobs(&self, include_paths: bool) -> Vec<PluginBlobGrant> {
        self.blobs
            .iter()
            .map(|(hash, blob)| PluginBlobGrant {
                hash: hash.clone(),
                size_bytes: blob.size_bytes,
                path: include_paths
                    .then(|| guest_blob_path(hash))
                    .filter(|_| blob.object_path.is_some()),
            })
            .collect()
    }
}

pub(super) fn plugin_manifest_json(
    grant: &GrantedSnapshot,
    include_paths: bool,
) -> Result<String> {
    grant.manifest_json(include_paths)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginInvocationManifest {
    blobs: Vec<PluginBlobGrant>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginBlobGrant {
    hash: Blake3Hash,
    size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

fn guest_blob_path(hash: &Blake3Hash) -> String {
    format!("/snapshot/{}", hash.as_str())
}
