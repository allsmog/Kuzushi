#[cfg(test)]
mod tests {
    use super::super::*;

    #[tokio::test]
    async fn resolve_returns_pre_existing_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("compile_commands.json");
        tokio::fs::write(&path, "[]").await.unwrap();
        let db = resolve(tmp.path()).await.unwrap();
        assert!(matches!(db.generator, Generator::PreExisting));
        assert_eq!(db.path, path);
        assert_eq!(db.entries, 0);
    }

    #[tokio::test]
    async fn resolve_returns_none_when_no_database_findable() {
        let tmp = tempfile::tempdir().unwrap();
        let db = resolve(tmp.path()).await.unwrap();
        assert!(matches!(db.generator, Generator::None));
        assert_eq!(db.entries, 0);
    }

    #[tokio::test]
    async fn count_entries_handles_real_db() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("compile_commands.json");
        let body = r#"[
            {"directory":"/r","command":"clang -c a.c","file":"a.c"},
            {"directory":"/r","command":"clang -c b.c","file":"b.c"}
        ]"#;
        tokio::fs::write(&path, body).await.unwrap();
        assert_eq!(count_entries(&path).await.unwrap(), 2);
    }
}
