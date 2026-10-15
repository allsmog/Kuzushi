use super::*;

/// Use captured source membership; partition guidance never starts another walk.
pub(super) fn count_partition_sources(paths: &[TaintIrisNextSourcePath]) -> usize {
    paths
        .iter()
        .filter(|source| is_partition_source(&source.absolute_path))
        .take(2_000)
        .count()
}

fn is_partition_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("c" | "cpp" | "cc" | "cxx")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(name: &str) -> TaintIrisNextSourcePath {
        TaintIrisNextSourcePath {
            absolute_path: PathBuf::from(name),
            relative_path: name.into(),
            language: "owned".into(),
        }
    }

    #[test]
    fn counts_only_c_family_sources_in_the_supplied_inventory() {
        assert_eq!(
            count_partition_sources(&[
                source("owned.c"),
                source("owned.cpp"),
                source("owned.cc"),
                source("owned.cxx"),
                source("owned.h"),
                source("owned.rs")
            ]),
            4
        );
    }

    #[test]
    fn partition_count_saturates_without_reading_source_files() {
        let paths = vec![source("does-not-exist.c"); 2_001];
        assert_eq!(count_partition_sources(&paths), 2_000);
    }
}
