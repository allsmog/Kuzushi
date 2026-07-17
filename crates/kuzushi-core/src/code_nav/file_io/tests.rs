#[cfg(test)]
mod tests {
    use super::super::*;
    use std::{fs, path::Path};
    use tempfile::tempdir;

    fn write_lines(dir: &Path, name: &str, n: usize) -> std::path::PathBuf {
        let body: String = (1..=n).map(|i| format!("line {i}\n")).collect();
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn full_read_returns_every_line() {
        let tmp = tempdir().unwrap();
        write_lines(tmp.path(), "a.rs", 5);
        let out = read_source(
            tmp.path(),
            &ReadSourceInput {
                file: "a.rs".to_string(),
                start_line: None,
                end_line: None,
            },
        )
        .unwrap();
        assert_eq!(out.total_lines, 5);
        assert_eq!(out.start_line, 1);
        assert_eq!(out.end_line, 5);
        assert_eq!(out.contents, "line 1\nline 2\nline 3\nline 4\nline 5\n");
        assert!(!out.truncated);
    }

    #[test]
    fn line_range_is_inclusive_1_indexed() {
        let tmp = tempdir().unwrap();
        write_lines(tmp.path(), "a.rs", 10);
        let out = read_source(
            tmp.path(),
            &ReadSourceInput {
                file: "a.rs".to_string(),
                start_line: Some(3),
                end_line: Some(5),
            },
        )
        .unwrap();
        assert_eq!(out.contents, "line 3\nline 4\nline 5\n");
    }

    #[test]
    fn overshooting_end_line_clamps_to_total() {
        let tmp = tempdir().unwrap();
        write_lines(tmp.path(), "a.rs", 4);
        let out = read_source(
            tmp.path(),
            &ReadSourceInput {
                file: "a.rs".to_string(),
                start_line: Some(2),
                end_line: Some(99),
            },
        )
        .unwrap();
        assert_eq!(out.end_line, 4);
    }

    #[test]
    fn truncates_huge_reads_and_marks_flag() {
        let tmp = tempdir().unwrap();
        let body = "a".repeat(MAX_READ_BYTES + 100);
        fs::write(tmp.path().join("big.rs"), body).unwrap();
        let out = read_source(
            tmp.path(),
            &ReadSourceInput {
                file: "big.rs".to_string(),
                start_line: None,
                end_line: None,
            },
        )
        .unwrap();
        assert!(out.truncated);
        assert!(out.contents.contains("[truncated"));
    }

    #[test]
    fn rejects_path_escape() {
        let tmp = tempdir().unwrap();
        let inner = tmp.path().join("inner");
        fs::create_dir_all(&inner).unwrap();
        fs::write(tmp.path().join("outside.txt"), "secret").unwrap();
        let err = read_source(
            &inner,
            &ReadSourceInput {
                file: "../outside.txt".to_string(),
                start_line: None,
                end_line: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("read_source"));
    }

    #[test]
    fn rejects_oversized_source_without_reading_it_whole() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("huge.rs");
        fs::write(&path, "fn main() {}\n").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(8 * 1024 * 1024 + 1)
            .unwrap();

        let error = read_source(
            tmp.path(),
            &ReadSourceInput {
                file: "huge.rs".to_string(),
                start_line: Some(1),
                end_line: Some(2),
            },
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("maximum supported size"));
    }
}
