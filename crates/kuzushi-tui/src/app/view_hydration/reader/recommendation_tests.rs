use super::*;

#[test]
fn saved_advice_hydrates_without_git_and_rejects_damaged_findings() {
    let root = tempfile::tempdir().unwrap();
    let reader = FsViewArtifactReader;
    let cancellation = ViewHydrationCancellation::default();
    let value = reader
        .read_cancellable(
            root.path(),
            &ViewHydrationKey::ScanRecommendations,
            &cancellation,
        )
        .unwrap();
    assert!(matches!(
        value,
        ViewHydrationValue::ScanRecommendations(ScanRecommendationsState::Ready(_))
    ));
    assert!(!root.path().join(".kuzushi").exists());
    let path = kuzushi_core::workspace::workspace_findings_db_path(root.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"Owned invalid database").unwrap();
    let value = reader
        .read_cancellable(
            root.path(),
            &ViewHydrationKey::ScanRecommendations,
            &cancellation,
        )
        .unwrap();
    assert!(matches!(
        value,
        ViewHydrationValue::ScanRecommendations(ScanRecommendationsState::Failed(_))
    ));
    cancellation.cancel();
    assert!(reader
        .read_cancellable(
            root.path(),
            &ViewHydrationKey::ScanRecommendations,
            &cancellation
        )
        .is_none());
}
