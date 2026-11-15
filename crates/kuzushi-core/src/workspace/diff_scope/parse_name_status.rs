use super::*;

/// The changed files in one `git diff --name-status -z` stdout.
///
/// `-z` frames every record as its raw bytes followed by NUL: a status code,
/// then the new path, and for a rename or a copy the old path before it. None
/// of those names is quoted or escaped, which is why this reader asks for `-z`
/// rather than decoding git's human-readable output.
pub(crate) fn parse_name_status(stdout: &[u8]) -> Result<BTreeMap<String, ChangedFile>> {
    let records = crate::git_nul_paths::nul_separated_paths(stdout, "whitebox diff scope")?;
    let mut files = BTreeMap::new();
    let mut rest = records.as_slice();
    while let Some((code, tail)) = rest.split_first() {
        let (file, remaining) = changed_file_record(code, tail)?;
        files.insert(file.path.clone(), file);
        rest = remaining;
    }
    Ok(files)
}

/// The one entry the status code `code` opens, plus the records after it.
///
/// A truncated entry is an error rather than a dropped file: this reader is
/// the whole list of what a pull request changed, and a silently short list
/// narrows the report without saying so.
fn changed_file_record<'a>(
    code: &str,
    tail: &'a [String],
) -> Result<(ChangedFile, &'a [String])> {
    let status = status_from_name_status(code);
    let carries_old_path = matches!(status, DiffFileStatus::Renamed | DiffFileStatus::Copied);
    let wanted = if carries_old_path { 2 } else { 1 };
    let paths = tail.get(..wanted).with_context(|| {
        format!("whitebox diff scope: git --name-status -z ended after the status code {code:?}")
    })?;
    Ok((
        ChangedFile {
            path: paths[wanted - 1].clone(),
            previous_path: carries_old_path.then(|| paths[0].clone()),
            status,
            changed_ranges: Vec::new(),
            deleted_ranges: Vec::new(),
        },
        &tail[wanted..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_raw_name_of_every_record_including_a_rename() {
        let files =
            parse_name_status("M\0src/café.rs\0R100\0old\u{ef}.rs\0new\u{ef}.rs\0A\0trail \0".as_bytes())
                .unwrap();

        assert_eq!(
            files.keys().cloned().collect::<Vec<_>>(),
            vec![
                "new\u{ef}.rs".to_string(),
                "src/café.rs".to_string(),
                "trail ".to_string(),
            ]
        );
        assert_eq!(files["src/café.rs"].status, DiffFileStatus::Modified);
        assert_eq!(files["new\u{ef}.rs"].status, DiffFileStatus::Renamed);
        assert_eq!(
            files["new\u{ef}.rs"].previous_path.as_deref(),
            Some("old\u{ef}.rs")
        );
        assert_eq!(files["trail "].previous_path, None);
    }

    #[test]
    fn an_entry_without_its_path_is_an_error_rather_than_a_dropped_file() {
        let error = parse_name_status(b"M\0src/a.rs\0R100\0only-one.rs\0")
            .unwrap_err()
            .to_string();

        assert!(error.contains("ended after the status code"), "{error}");
    }

    #[test]
    fn output_that_is_not_nul_framed_is_an_error() {
        assert!(parse_name_status(b"M\tsrc/a.rs\n").is_err());
    }
}
