#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn read_head_commit_returns_none_for_non_repo() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_head_commit(tmp.path()).is_none());
    }

    #[test]
    fn read_head_commit_handles_detached_head() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("HEAD"), "deadbeef1234abcd5678\n").unwrap();
        let commit = read_head_commit(tmp.path()).unwrap();
        assert_eq!(commit, "deadbeef1234");
    }

    #[test]
    fn read_head_commit_handles_symbolic_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            git_dir.join("refs/heads/main"),
            "1234567890abcdef1234567890\n",
        )
        .unwrap();
        let commit = read_head_commit(tmp.path()).unwrap();
        assert_eq!(commit, "1234567890ab");
    }
}
