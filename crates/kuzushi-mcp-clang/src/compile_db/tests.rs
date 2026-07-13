#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_mcp_common::ReadRootCapability;
    use std::path::Path;

    fn authorized_repo(
        root: &tempfile::TempDir,
    ) -> (ReadRootCapability, kuzushi_mcp_common::AuthorizedDirectory) {
        let read = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
        let repo = read.authorize_directory(root.path()).unwrap();
        (read, repo)
    }

    #[tokio::test]
    async fn resolve_returns_pre_existing_when_present() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("compile_commands.json");
        std::fs::write(&path, "[]").unwrap();
        let (_read, repo) = authorized_repo(&root);

        let database = resolve(&repo).await.unwrap();

        assert!(matches!(database.generator, Generator::PreExisting));
        assert_eq!(database.path, path.canonicalize().unwrap());
        assert_eq!(database.entries, 0);
    }

    #[tokio::test]
    async fn resolve_returns_none_without_running_generators() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("CMakeLists.txt"),
            "message(FATAL_ERROR nope)",
        )
        .unwrap();
        let (_read, repo) = authorized_repo(&root);

        let database = resolve(&repo).await.unwrap();

        assert!(matches!(database.generator, Generator::None));
        assert_eq!(database.entries, 0);
        assert!(!root.path().join("build").exists());
    }

    #[test]
    fn count_entries_handles_a_bounded_database() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("compile_commands.json");
        let body = r#"[
            {"directory":"/r","command":"clang -c a.c","file":"a.c"},
            {"directory":"/r","command":"clang -c b.c","file":"b.c"}
        ]"#;
        std::fs::write(&path, body).unwrap();
        let (_read, repo) = authorized_repo(&root);
        let opened = repo
            .open_file(Path::new("compile_commands.json"), body.len())
            .unwrap();

        assert_eq!(count_entries(opened).unwrap(), 2);
    }

    #[tokio::test]
    async fn oversized_database_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("compile_commands.json");
        let file = std::fs::File::create(path).unwrap();
        file.set_len((8 * 1024 * 1024 + 1) as u64).unwrap();
        let (_read, repo) = authorized_repo(&root);

        let error = resolve(&repo).await.unwrap_err();

        assert!(error.to_string().contains("8388608 bytes"));
    }
}
