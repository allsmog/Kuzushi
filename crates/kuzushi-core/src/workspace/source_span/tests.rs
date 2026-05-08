#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn source_span_extracts_repo_relative_snippet_and_hash() {
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("routes.ts"),
            "import express from 'express'\napp.get('/a', handler)\napp.post('/b', save)\n",
        )
        .unwrap();

        let span = extract_source_span(temp.path(), "src/routes.ts", 2, 3).unwrap();

        assert_eq!(span.file_path, "src/routes.ts");
        assert_eq!(span.start_line, 2);
        assert_eq!(span.end_line, 3);
        assert_eq!(span.snippet, "app.get('/a', handler)\napp.post('/b', save)");
        assert_eq!(span.content_hash, static_content_hash(&span.snippet));
    }

    #[test]
    fn source_span_accepts_absolute_paths_under_repo_root() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("main.rs");
        fs::write(&file, "fn main() {}\n").unwrap();

        let span = extract_source_span(temp.path(), &file, 1, 1).unwrap();

        assert_eq!(span.file_path, "main.rs");
        assert_eq!(span.snippet, "fn main() {}");
    }

    #[test]
    fn source_span_rejects_missing_files() {
        let temp = tempfile::tempdir().unwrap();

        let error = extract_source_span(temp.path(), "missing.rs", 1, 1)
            .unwrap_err()
            .to_string();

        assert!(error.contains("does not exist"), "{error}");
    }

    #[test]
    fn source_span_rejects_binaryish_files() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("blob.bin"), b"abc\0def").unwrap();

        let error = extract_source_span(temp.path(), "blob.bin", 1, 1)
            .unwrap_err()
            .to_string();

        assert!(error.contains("binary or non-text"), "{error}");
    }

    #[test]
    fn source_span_rejects_bad_line_ranges() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("app.py"), "one\ntwo\n").unwrap();

        let zero = extract_source_span(temp.path(), "app.py", 0, 1)
            .unwrap_err()
            .to_string();
        let reversed = extract_source_span(temp.path(), "app.py", 2, 1)
            .unwrap_err()
            .to_string();
        let too_long = extract_source_span(temp.path(), "app.py", 1, 3)
            .unwrap_err()
            .to_string();

        assert!(zero.contains("1-based"), "{zero}");
        assert!(reversed.contains("after end line"), "{reversed}");
        assert!(too_long.contains("exceeds file line count"), "{too_long}");
    }

    #[test]
    fn source_span_rejects_traversal_and_out_of_repo_paths() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "secret\n").unwrap();

        let traversal = extract_source_span(temp.path(), "../outside.rs", 1, 1)
            .unwrap_err()
            .to_string();
        let outside = extract_source_span(temp.path(), outside.path(), 1, 1)
            .unwrap_err()
            .to_string();

        assert!(traversal.contains("parent traversal"), "{traversal}");
        assert!(outside.contains("outside repository root"), "{outside}");
    }
}
