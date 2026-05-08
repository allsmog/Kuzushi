#[cfg(test)]
mod tests {
    use super::super::*;
    use std::path::PathBuf;

    /// Known SHA-256 of the empty string — sanity check the hand-rolled hash.
    #[test]
    fn sha256_of_empty_matches_known_vector() {
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Known SHA-256 of "abc".
    #[test]
    fn sha256_of_abc_matches_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Repo hash is stable for the same path/remote pair.
    #[test]
    fn repo_hash_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let a = repo_hash(tmp.path()).unwrap();
        let b = repo_hash(tmp.path()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.hash.len(), 64);
    }

    #[test]
    fn read_git_remote_finds_origin_url_only_inside_origin_block() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(
            git_dir.join("config"),
            r#"
[remote "upstream"]
    url = git@example.com:wrong/repo.git
[remote "origin"]
    fetch = +refs/heads/*:refs/remotes/origin/*
    url = git@example.com:org/repo.git
"#,
        )
        .unwrap();

        assert_eq!(
            read_git_remote(tmp.path()).as_deref(),
            Some("git@example.com:org/repo.git")
        );
    }

    #[test]
    fn manifest_round_trips() {
        let manifest = CacheManifest {
            repos: vec![RepoEntry {
                fingerprint: RepoFingerprint {
                    canonical_path: PathBuf::from("/tmp/repo"),
                    git_remote: Some("git@github.com:foo/bar.git".to_string()),
                    hash: "abc123".to_string(),
                },
                backends: vec![BackendEntry {
                    backend: "gtags".to_string(),
                    last_indexed: "2026-05-06T00:00:00Z".to_string(),
                    commit: Some("deadbeef".to_string()),
                    size_bytes: 1024,
                }],
            }],
        };
        let s = serde_json::to_string(&manifest).unwrap();
        let back: CacheManifest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.repos.len(), 1);
        assert_eq!(back.repos[0].fingerprint.hash, "abc123");
    }
}
