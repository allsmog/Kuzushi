//! Persisted identity for producers whose rule and file alone do not name one
//! issue: distinct issues must stay distinct, and a re-observed issue must
//! corroborate its existing identity instead of minting a new one.

use crate::dep_hygiene::DepHygieneScanner;
use crate::findings::{
    Finding, FindingIdentityBasis, FindingListFilter, FindingStore, IdentityFoldPolicy, Severity,
};
use crate::iac_scan::IacScanScanner;
use crate::scan::{ScanCancellation, ScanEngine};
use crate::secret_scan::SecretScanScanner;
use std::collections::BTreeSet;
use std::path::Path;

const TWO_SECURITY_GROUPS: &str = r#"resource "aws_security_group" "alb" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs" {
  egress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;

fn open_store(target: &Path) -> FindingStore {
    FindingStore::open(target.join("findings.db")).unwrap()
}

fn persist_scan(store: &FindingStore, target: &Path, run_id: &str, engine: &dyn ScanEngine) {
    let findings = engine.scan(target, &ScanCancellation::default()).unwrap();
    store.record_run_started(run_id, target, "running").unwrap();
    store.insert_findings(run_id, &findings).unwrap();
}

fn scan_scope(store: &FindingStore, runs: &[&str], policy: IdentityFoldPolicy) -> Vec<Finding> {
    store
        .list_distinct_findings_for_scan_ids_with_identity_policy(runs, policy)
        .unwrap()
}

fn identities(findings: &[Finding]) -> BTreeSet<String> {
    findings
        .iter()
        .filter_map(|finding| finding.identity_id.clone())
        .collect()
}

#[test]
fn repeated_producer_observation_uses_the_same_safe_projection_as_review() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("source.rs"), "fn greet() {}\n").unwrap();
    let store = open_store(target.path());
    let mut finding = Finding::new_tool(
        "agentic",
        "same-observation",
        "source.rs",
        1,
        None,
        Severity::Info,
        "Repeated source observation",
    );
    finding.fingerprint = "producer-fingerprint".into();
    finding.source_signature = Some("same-grounded-source".into());
    for run in ["first-pass", "second-pass"] {
        store
            .record_run_started(run, target.path(), "running")
            .unwrap();
        store.insert_finding(run, &finding).unwrap();
    }
    let runs = ["first-pass", "second-pass"];
    let findings = scan_scope(&store, &runs, IdentityFoldPolicy::Safe);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        store
            .count_finding_observations_for_scan_ids(&runs)
            .unwrap(),
        2
    );
    assert_eq!(store.list_all_findings().unwrap().len(), 1);
    assert!(findings[0]
        .sources
        .iter()
        .any(|source| source.first_scan_id == "first-pass"));
    assert!(findings[0]
        .sources
        .iter()
        .any(|source| source.last_scan_id == "second-pass"));
}

#[test]
fn two_packages_in_one_manifest_keep_two_identities() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"dependencies":{"clarinet":"^0.12.6"},"devDependencies":{"neostandard":"^0.13.0"}}"#,
    )
    .unwrap();
    let store = open_store(tmp.path());
    persist_scan(&store, tmp.path(), "run-deps", &DepHygieneScanner);

    let rows = store.list_findings_for_scan_id("run-deps").unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(identities(&rows).len(), 2);
    assert!(rows
        .iter()
        .all(|row| row.identity_basis == Some(FindingIdentityBasis::SourceLocator)));
    assert!(rows.iter().all(|row| row.corroboration_count == 1));
}

#[test]
fn two_terraform_resources_keep_two_identities() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("networking.tf"), TWO_SECURITY_GROUPS).unwrap();
    let store = open_store(tmp.path());
    persist_scan(&store, tmp.path(), "run-iac", &IacScanScanner::default());

    let rows = store.list_findings_for_scan_id("run-iac").unwrap();
    let locators = rows
        .iter()
        .filter_map(|row| row.symbol_locator.clone())
        .collect::<BTreeSet<_>>();

    assert_eq!(rows.len(), 2);
    assert_eq!(identities(&rows).len(), 2);
    assert_eq!(
        locators,
        [
            "aws_security_group.alb.ingress[0].cidr_blocks",
            "aws_security_group.ecs.egress[0].cidr_blocks",
        ]
        .map(String::from)
        .into()
    );
}

#[test]
fn same_issue_observed_twice_corroborates_one_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("networking.tf");
    std::fs::write(&manifest, TWO_SECURITY_GROUPS).unwrap();
    let store = open_store(tmp.path());
    persist_scan(&store, tmp.path(), "run-first", &IacScanScanner::default());
    // An unrelated edit moves every line; the structural locator still names
    // the same two blocks.
    std::fs::write(&manifest, format!("# networking\n\n{TWO_SECURITY_GROUPS}")).unwrap();
    persist_scan(&store, tmp.path(), "run-second", &IacScanScanner::default());

    let first = identities(&store.list_findings_for_scan_id("run-first").unwrap());
    let second = identities(&store.list_findings_for_scan_id("run-second").unwrap());
    let filter = FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT);
    let ledger = store
        .list_findings_filtered_with_identity_policy(&filter, IdentityFoldPolicy::Safe)
        .unwrap()
        .findings;

    assert_eq!(first, second);
    assert_eq!(ledger.len(), 2);
    assert!(ledger
        .iter()
        .all(|finding| finding.corroboration_count == 2));
}

#[test]
fn repeated_secret_occurrences_keep_one_identity_each() {
    let tmp = tempfile::tempdir().unwrap();
    let key = concat!(
        "OPENAI_API_KEY=sk-",
        "proj-abcdefghijklmnopqrstuvwxyzABCDEFGH"
    );
    std::fs::write(
        tmp.path().join("keys.txt"),
        format!("{key}\nlogin();\n{key}\n"),
    )
    .unwrap();
    let store = open_store(tmp.path());
    persist_scan(&store, tmp.path(), "run-secrets", &SecretScanScanner);

    let rows = store.list_findings_for_scan_id("run-secrets").unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(identities(&rows).len(), 2);
}

/// A producer without a structural locator still mints one weak identity for
/// identical statements; the run-scoped count must not fold them.
#[test]
fn run_distinct_findings_never_fold_distinct_weak_identity_observations() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("test")).unwrap();
    std::fs::write(
        tmp.path().join("test/login.test.ts"),
        "const token = 'eyJhbGciOi';\nlogin();\nconst token = 'eyJhbGciOi';\n",
    )
    .unwrap();
    let store = open_store(tmp.path());
    store
        .record_run_started("run-lines", tmp.path(), "running")
        .unwrap();
    for line in [1, 3] {
        let mut finding = Finding::new_tool(
            "line-scanner",
            "line-scanner/token",
            "test/login.test.ts",
            line,
            None,
            Severity::High,
            "Token literal",
        );
        finding.fingerprint = format!("line-scanner:token:{line}");
        store.insert_finding("run-lines", &finding).unwrap();
    }

    let rows = store.list_findings_for_scan_id("run-lines").unwrap();
    let distinct = scan_scope(&store, &["run-lines"], IdentityFoldPolicy::Safe);

    assert_eq!(identities(&rows).len(), 1, "identical statements stay weak");
    assert_eq!(distinct.len(), 2);
    assert_eq!(
        store
            .count_finding_observations_for_scan_ids(&["run-lines"])
            .unwrap(),
        2
    );
}

fn secret_in_one_bucket(line: u32, locator: &str, fingerprint: &str) -> Finding {
    let mut finding = Finding::new_tool(
        "secret-scan",
        "secret/aws-access-key",
        "src/config.js",
        line,
        None,
        Severity::High,
        "Hardcoded AWS access key (CWE-798)",
    );
    finding.fingerprint = fingerprint.into();
    finding.symbol_locator = Some(locator.into());
    finding
}

/// Two secrets inside one dedup bucket: distinct source-locator identities
/// over one shared dedup key, so the policies genuinely disagree about how
/// many findings these runs hold. The ledger an operator reads beside a scan
/// receipt folds the corpus through the effective identity-fold policy, which
/// the approval gate keeps at `legacy` until an operator approves the identity
/// audit. A run-scoped reader that chose `Safe` for itself therefore reported
/// one more finding than the ledger directly above it.
#[test]
fn a_run_scoped_count_folds_like_the_ledger_under_every_policy() {
    let target = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(target.path().join("src")).unwrap();
    std::fs::write(target.path().join("src/config.js"), "a\nb\nc\n").unwrap();
    let store = open_store(target.path());
    store
        .record_run_started("run-native", target.path(), "running")
        .unwrap();
    store
        .insert_findings(
            "run-native",
            &[
                secret_in_one_bucket(1, "secret:aws:aaa#1", "fp-first"),
                secret_in_one_bucket(2, "secret:aws:bbb#1", "fp-second"),
            ],
        )
        .unwrap();

    let runs = ["run-native"];
    let counted = |policy| scan_scope(&store, &runs, policy).len();
    let ledger = |policy| {
        store
            .list_relevant_findings_with_identity_policy(policy)
            .unwrap()
            .len()
    };

    for policy in [
        IdentityFoldPolicy::Legacy,
        IdentityFoldPolicy::Safe,
        IdentityFoldPolicy::Aggressive,
    ] {
        assert_eq!(
            counted(policy),
            ledger(policy),
            "{policy:?}: the run-scoped count disagreed with the ledger"
        );
    }
    assert_eq!(counted(IdentityFoldPolicy::Legacy), 1);
    assert_eq!(counted(IdentityFoldPolicy::Safe), 2);
}
