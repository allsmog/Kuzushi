use super::*;

#[test]
fn nameless_directories_are_coverage_gaps_without_more_work() {
    let root = tempfile::tempdir().unwrap();
    for path in [Path::new(""), Path::new("/"), Path::new("..")] {
        let mut files = Vec::new();
        let mut gaps = CoverageGaps::default();
        let mut inspection = IacInspection::default();
        let mut pending = Vec::new();
        IacWalk {
            root: root.path(),
            options: &IacScanOptions::default(),
            cancellation: &ScanCancellation::default(),
            files: &mut files,
            gaps: &mut gaps,
            inspection: &mut inspection,
        }
        .directory_entry(path, 0, &mut pending);
        assert!(pending.is_empty());
        assert!(files.is_empty());
        assert_eq!(gaps.total(), 1);
        assert_eq!(gaps.gaps[0].kind, CoverageGapKind::Directory);
        assert!(gaps.gaps[0].reason.contains("no final path component"));
        assert_eq!(inspection, IacInspection::default());
    }
}
