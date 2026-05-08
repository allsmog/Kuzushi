use super::*;

pub(crate) fn parse_name_status(output: &str) -> BTreeMap<String, ChangedFile> {
    let mut files = BTreeMap::new();
    for line in output.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() < 2 {
            continue;
        }
        let code = fields[0];
        let status = status_from_name_status(code);
        let (previous_path, path) =
            if matches!(status, DiffFileStatus::Renamed | DiffFileStatus::Copied)
                && fields.len() >= 3
            {
                (
                    Some(normalize_repo_path(fields[1])),
                    normalize_repo_path(fields[2]),
                )
            } else {
                (None, normalize_repo_path(fields[1]))
            };
        files.insert(
            path.clone(),
            ChangedFile {
                path,
                previous_path,
                status,
                changed_ranges: Vec::new(),
                deleted_ranges: Vec::new(),
            },
        );
    }
    files
}
