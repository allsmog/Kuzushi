//! Postgres-shape target partitioning.
//!
//! When an operator points kuzushi at the full PostgreSQL mainline
//! tree (`/tmp/targets/pg`, 1612 .c files, 4.5GB), running joern's
//! `reachableByFlows` across the whole CPG with a broad CWE catalog
//! hangs (orafce-shape exponential blow-up on broad `appendStringInfo`
//! / `elog` regexes). Two responses:
//!
//! 1. The operator passes `--input '{"targetSubdir":"contrib/dblink"}'`
//!    (E2a, lands the wiring).
//! 2. They run several partitioned hunts in parallel via shell
//!    orchestration:
//!       for subdir in $(recommended); do
//!         kuzushi run taint-iris-next:hunt \
//!           --target /tmp/targets/pg \
//!           --input "{\"targetSubdir\":\"$subdir\"}" &
//!       done; wait
//!
//! This module owns the postgres-shape partition recommendation
//! returned to the operator at plan time (surfaced via a plan
//! warning when `target_subdir` is None and the target looks
//! postgres-shaped). It is intentionally deterministic, hardcoded,
//! and cheap — no LLM call to decide which directories matter.
//! Operators with novel layouts ignore the recommendation and pass
//! `targetSubdir` manually.
//!
//! Why not auto-spawn parallel hunts inside one tool invocation?
//! Joern's REPL launcher writes per-CPG state under
//! `<cwd>/workspace/<cpg-name>` and concurrent runs against the
//! same CPG fight over it. Each partitioned hunt is a separate
//! process with its own working directory; that's the operator's
//! job to orchestrate. The kuzushi tool just tells them how.

use std::path::{Path, PathBuf};

/// Heuristic: a postgres-shape target has both `src/backend` and
/// `src/interfaces/libpq` directories at the top level. We use the
/// directory existence rather than file count so a tarball that's
/// been partially extracted still gets recognised.
pub(in crate::modules) fn looks_postgres_shaped(target: &Path) -> bool {
    target.join("src/backend").is_dir() && target.join("src/interfaces/libpq").is_dir()
}

/// Default postgres partition recommendation. Each entry is a
/// repo-relative subdir suitable as `targetSubdir`. The list
/// prioritises:
///
/// - newer-attack-surface subsystems (OAuth in libpq + libpq-oauth)
/// - parser-shape code (jsonpath, regex, libpq client-side wire parser)
/// - replication / WAL (touchpoints for malicious-server scenarios)
/// - contribs that have had recent CVE history (postgres_fdw, dblink, pgcrypto)
///
/// The partition list is hardcoded for postgres mainline. For
/// non-postgres targets, `looks_postgres_shaped` returns false and
/// callers fall back to a single whole-tree hunt.
pub(in crate::modules) fn postgres_partition_recommendation() -> &'static [&'static str] {
    &[
        // ----- Client-side (libpq) — pre-auth attack surface -----
        "src/interfaces/libpq",
        "src/interfaces/libpq-oauth",
        // ----- Server-side auth + OAuth (PG17 surface) -----
        "src/backend/libpq",
        // ----- Replication / WAL (rogue-publisher / -subscriber) -----
        "src/backend/replication",
        // ----- ADT / parsers (jsonpath, regex, ts*) -----
        "src/backend/utils/adt",
        // ----- Access / transam (2PC / WAL recovery) -----
        "src/backend/access",
        // ----- CLI binaries (pg_dump, pg_restore, pg_basebackup) -----
        "src/bin/pg_dump",
        "src/bin/pg_restore",
        "src/bin/pg_basebackup",
        // ----- Contrib modules with recent CVE / SQL injection
        //       precedent (postgres_fdw + dblink were the source of
        //       the cursor-name finding kuzushi shipped) -----
        "contrib/postgres_fdw",
        "contrib/dblink",
        "contrib/pgcrypto",
        // ----- Other notable contribs (intarray, ltree, hstore,
        //       earthdistance, tablefunc, pageinspect) — bucket
        //       under one partition because individually small -----
        "contrib",
    ]
}

/// Filter the recommendation to subdirs that actually exist under
/// `target`. Lets the partition map stay stable across postgres
/// release branches even when a directory has been renamed or
/// removed.
pub(in crate::modules) fn postgres_partitions_for(target: &Path) -> Vec<PathBuf> {
    if !looks_postgres_shaped(target) {
        return Vec::new();
    }
    postgres_partition_recommendation()
        .iter()
        .filter_map(|subdir| {
            let abs = target.join(subdir);
            abs.is_dir().then(|| PathBuf::from(*subdir))
        })
        .collect()
}

/// Number of .c files threshold above which the partition
/// recommendation kicks in. Smaller targets (pgcrypto-vuln, a single
/// contrib module) don't need partitioning even if they happen to
/// match `looks_postgres_shaped`.
const PARTITION_THRESHOLD_C_FILES: usize = 500;

/// True iff the operator should be advised to partition. Returns
/// true when:
/// - the target looks postgres-shaped
/// - AND there are more than `PARTITION_THRESHOLD_C_FILES` .c files
/// Operators can suppress the warning by passing `targetSubdir`
/// (which makes the recommendation moot — they've already narrowed).
pub(in crate::modules) fn should_recommend_partitioning(
    target: &Path,
    c_file_count: usize,
) -> bool {
    looks_postgres_shaped(target) && c_file_count > PARTITION_THRESHOLD_C_FILES
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn looks_postgres_shaped_requires_both_signature_dirs() {
        let temp = tempdir().unwrap();
        let target = temp.path();
        assert!(!looks_postgres_shaped(target));
        fs::create_dir_all(target.join("src/backend")).unwrap();
        assert!(!looks_postgres_shaped(target));
        fs::create_dir_all(target.join("src/interfaces/libpq")).unwrap();
        assert!(looks_postgres_shaped(target));
    }

    #[test]
    fn postgres_partitions_for_filters_to_existing_dirs() {
        let temp = tempdir().unwrap();
        let target = temp.path();
        fs::create_dir_all(target.join("src/backend")).unwrap();
        fs::create_dir_all(target.join("src/interfaces/libpq")).unwrap();
        fs::create_dir_all(target.join("contrib/dblink")).unwrap();
        // Don't create contrib/pgcrypto — should be filtered out.
        let partitions = postgres_partitions_for(target);
        assert!(
            partitions
                .iter()
                .any(|p| p == &PathBuf::from("contrib/dblink"))
        );
        assert!(
            !partitions
                .iter()
                .any(|p| p == &PathBuf::from("contrib/pgcrypto")),
            "non-existent dirs must be filtered: {partitions:?}"
        );
        // libpq client + libpq server are both expected to exist
        assert!(
            partitions
                .iter()
                .any(|p| p == &PathBuf::from("src/interfaces/libpq")),
        );
    }

    #[test]
    fn non_postgres_target_returns_empty_partitions() {
        let temp = tempdir().unwrap();
        // No src/backend or src/interfaces/libpq.
        fs::create_dir_all(temp.path().join("lib/foo")).unwrap();
        assert!(postgres_partitions_for(temp.path()).is_empty());
    }

    #[test]
    fn partition_list_includes_known_high_eight_subsystems() {
        let recommended = postgres_partition_recommendation();
        // Subsystems we KNOW have surfaced findings in past hunts —
        // their presence in the recommendation is a regression gate.
        for must_include in &[
            "src/interfaces/libpq",
            "src/interfaces/libpq-oauth",
            "src/backend/libpq",
            "src/backend/access",
            "contrib/postgres_fdw",
            "contrib/dblink",
            "contrib/pgcrypto",
            "src/bin/pg_dump",
        ] {
            assert!(
                recommended.contains(must_include),
                "{must_include:?} must stay in the recommendation",
            );
        }
    }

    #[test]
    fn should_recommend_partitioning_only_for_huge_postgres_trees() {
        let temp = tempdir().unwrap();
        let target = temp.path();
        // Tiny tree (not postgres-shaped): no recommendation.
        assert!(!should_recommend_partitioning(target, 100));
        fs::create_dir_all(target.join("src/backend")).unwrap();
        fs::create_dir_all(target.join("src/interfaces/libpq")).unwrap();
        // postgres-shaped + small: still no.
        assert!(!should_recommend_partitioning(target, 100));
        // postgres-shaped + large: yes.
        assert!(should_recommend_partitioning(target, 1612));
        // Edge case: exactly at threshold = no (we use strict >).
        assert!(!should_recommend_partitioning(target, 500));
        assert!(should_recommend_partitioning(target, 501));
    }
}
