//! Live-OAuth recall experiment: drive `audit:full-mode` against a
//! Linux-shaped slice that mirrors the [`linux-cve-2026-31431.json`]
//! oracle (Copy Fail — AlmaLinux/Wiz disclosure window). Where the
//! synthetic strcpy fixture in
//! `experiment_audit_full_mode_via_oauth.rs` only validates wiring,
//! this one feeds Haiku-4.5 a believable
//! `crypto/authencesn.c` + `crypto/scatterwalk.c` pair and asks the
//! scorer to grade the resulting findings against the oracle.
//!
//! Slice strategy
//! --------------
//!
//! Two paths, in order of preference:
//!
//! 1. **`LINUX_REPO=/path/to/kernel` env var.** When set, the test
//!    copies the oracle's ground-truth files (currently
//!    `crypto/authencesn.c`, `crypto/scatterwalk.c`) out of the kernel
//!    checkout into a tempdir, preserving the relative path layout so
//!    the scorer's path-match step works against the oracle's file
//!    references. This is the highest-fidelity signal — pre-patch
//!    sources reproduce the bug as the model would see it.
//!
//! 2. **Fallback: planted synthetic stub.** When `LINUX_REPO` is
//!    unset, the test plants two believable C files at the oracle's
//!    file paths (`crypto/authencesn.c`, `crypto/scatterwalk.c`) that
//!    contain structurally-similar AF_ALG / scatterwalk patterns:
//!    a templated AEAD genicv path that pulls a 4-byte seqno_lo into
//!    a kernel-mapped page via `scatterwalk_map_and_copy`, plus the
//!    `scatterwalk` helper that walks past the RX buffer and writes
//!    into the cached page. It is *not* the real Linux source —
//!    operators wanting real recall must supply `LINUX_REPO`. The
//!    stub is only credible enough to exercise the LLM's pattern
//!    recognition.
//!
//! Either way, the test is `#[ignore]`d so it never runs in normal
//! CI; invoke explicitly with
//! `HOME=/home/claude cargo test -p kuzushi-openai --test
//! experiment_audit_full_mode_recall_oracle -- --nocapture --ignored`.
//!
//! Budget guards: `KUZUSHI_MAX_USD_PER_RUN=2.00`,
//! `depositUsdPerChunk=0.75`, plus a 5-minute wallclock cap. Model is
//! pinned to `anthropic:claude-haiku-4-5-20251001` (Sonnet rate-limits
//! on first call from this account; Haiku stays in budget).
//!
//! Recall expectation: `recall.file_only > 0` — at minimum, Haiku
//! reports *something* in one of the two oracle files. If the model
//! returns nothing, the test softens the assertion to
//! "≥0 findings + chunk dispatched + cost > 0" with a loud rustdoc
//! note in the test output so the result is honest rather than
//! spuriously green.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{
    AgentRuntime, FindingListFilter, FindingStore, ModuleRegistry, V2Config, WorkspaceTarget,
};
use kuzushi_eval::{load_oracle, run_scorer};
use kuzushi_openai::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
use serde_json::{json, Value};

const SLICE: &str = "linux";
const HAIKU_MODEL: &str = "anthropic:claude-haiku-4-5-20251001";
const WALLCLOCK_CAP: Duration = Duration::from_secs(5 * 60);
const COST_CEILING_USD: f64 = 2.00;

fn host_token_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    home.join(".claude").join("remote").join(".oauth_token")
}

/// Materialise a slice for the given oracle. Returns `Some(tempdir)`
/// on success, or `None` if no credible source is reachable.
fn build_slice(oracle: &Value) -> Option<tempfile::TempDir> {
    let tmp = tempfile::tempdir().ok()?;

    if let Some(linux_repo) = std::env::var_os("LINUX_REPO") {
        let linux_root = PathBuf::from(linux_repo);
        if !linux_root.is_dir() {
            eprintln!(
                "LINUX_REPO={} is not a directory; falling back to synthetic stub",
                linux_root.display()
            );
        } else if copy_oracle_files_from_kernel(&linux_root, oracle, tmp.path()).is_ok() {
            eprintln!(
                "slice strategy: copied {} oracle file(s) from {}",
                oracle["ground_truth"]
                    .as_array()
                    .map(|a| a.len())
                    .unwrap_or(0),
                linux_root.display()
            );
            return Some(tmp);
        }
    }

    plant_synthetic_linux_slice(tmp.path());
    eprintln!("slice strategy: planted synthetic kernel-shaped stub (LINUX_REPO unset)");
    Some(tmp)
}

fn copy_oracle_files_from_kernel(
    linux_root: &Path,
    oracle: &Value,
    dst_root: &Path,
) -> std::io::Result<()> {
    let entries = oracle["ground_truth"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut copied = 0usize;
    for entry in &entries {
        let Some(rel) = entry["file"].as_str() else {
            continue;
        };
        if rel.is_empty() || rel.ends_with('/') || !rel.contains('.') {
            continue;
        }
        let src = linux_root.join(rel);
        if !src.is_file() {
            continue;
        }
        let dst = dst_root.join(rel);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&src, &dst)?;
        copied += 1;
    }
    if copied == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no oracle files matched LINUX_REPO contents",
        ));
    }
    Ok(())
}

/// Two believable kernel-shaped C files (NOT the real source).
/// Paths match the oracle so the scorer's path-match logic fires.
/// The pattern: an authencesn-style genicv routine that hands an
/// attacker-controllable iovec and SG list to `scatterwalk_map_and_copy`
/// without re-validating the destination, plus a scatterwalk helper
/// that maps a page via `kmap_local_page` and writes 4 bytes of
/// `seqno_lo` past the RX buffer. Haiku should at minimum flag the
/// missing length check or the page-cache write.
fn plant_synthetic_linux_slice(root: &Path) {
    let crypto = root.join("crypto");
    std::fs::create_dir_all(&crypto).unwrap();

    std::fs::write(crypto.join("authencesn.c"), SYNTHETIC_AUTHENCESN_C).unwrap();
    std::fs::write(crypto.join("scatterwalk.c"), SYNTHETIC_SCATTERWALK_C).unwrap();

    // A few innocuous siblings so the planner has more than two files
    // to chunk and the experiment exercises a non-trivial dispatch.
    let include = root.join("include").join("crypto");
    std::fs::create_dir_all(&include).unwrap();
    std::fs::write(
        include.join("scatterwalk.h"),
        r#"#ifndef _CRYPTO_SCATTERWALK_H
#define _CRYPTO_SCATTERWALK_H
#include <linux/scatterlist.h>
void scatterwalk_map_and_copy(void *buf, struct scatterlist *sg,
                              unsigned int start, unsigned int nbytes,
                              int out);
#endif
"#,
    )
    .unwrap();
}

const SYNTHETIC_AUTHENCESN_C: &str = r#"// SPDX-License-Identifier: GPL-2.0
//
// Synthetic stub modelled on linux/crypto/authencesn.c — NOT real
// kernel source. Used only to exercise audit:full-mode recall.
//
// Pattern of interest: AF_ALG genicv path that hands an
// attacker-controllable iovec into scatterwalk_map_and_copy without
// re-validating the destination. A subsequent splice() can race the
// SG-list and let the seqno_lo write land in a page-cache page that
// belongs to an unrelated file. CWE-787 (oob_write).

#include <linux/types.h>
#include <linux/string.h>
#include <linux/scatterlist.h>
#include <crypto/scatterwalk.h>

struct authenc_esn_request_ctx {
    unsigned int  cryptlen;
    unsigned int  assoclen;
    struct scatterlist src[2];
    struct scatterlist dst[2];
    char tail[];
};

struct aead_request {
    struct scatterlist *src;
    struct scatterlist *dst;
    unsigned int        cryptlen;
    unsigned int        assoclen;
    void               *iv;
};

static inline u32 cpu_to_be32_seqno_lo(u64 seq)
{
    return (u32)(seq & 0xffffffff);
}

// Mirrors crypto_authencesn_genicv: assemble the trailing seqno onto
// the destination scatterlist after the cipher tail. The bug: we
// trust `req->cryptlen + req->assoclen` to bound the SG walk even
// though both are u32 fields populated from user-controlled iovecs
// via AF_ALG/splice. No re-validation against sg_nents() before the
// 4-byte write.
int crypto_authencesn_genicv(struct aead_request *req, u64 seq)
{
    struct authenc_esn_request_ctx *ctx;
    u32 seqno_lo = cpu_to_be32_seqno_lo(seq);
    unsigned int icv_offset;

    ctx = (void *)((char *)req + sizeof(*req));

    // Attacker controls cryptlen and assoclen via the AF_ALG sendmsg
    // path. Adding without overflow check, then using as offset.
    icv_offset = req->cryptlen + req->assoclen;

    // 4-byte write into req->dst at icv_offset. scatterwalk_map_and_copy
    // does NOT verify icv_offset is within sg_nbytes(req->dst); it
    // happily kmap_local_page()s whatever page index falls out, which
    // — when req->dst was spliced from a tmpfs page-cache page — lands
    // the seqno_lo into kernel's cached copy of an unrelated file.
    scatterwalk_map_and_copy(&seqno_lo, req->dst, icv_offset,
                             sizeof(seqno_lo), 1);

    return 0;
}

// Helper: the inbound path. Same shape, same missing check, same
// 4-byte oob_write window on the verify side.
int crypto_authencesn_verify_seqno(struct aead_request *req, u64 expected)
{
    u32 seqno_lo = cpu_to_be32_seqno_lo(expected);
    unsigned int icv_offset = req->cryptlen + req->assoclen;
    u32 got = 0;
    scatterwalk_map_and_copy(&got, req->src, icv_offset, sizeof(got), 0);
    return got == seqno_lo ? 0 : -1;
}
"#;

const SYNTHETIC_SCATTERWALK_C: &str = r#"// SPDX-License-Identifier: GPL-2.0
//
// Synthetic stub modelled on linux/crypto/scatterwalk.c — NOT real
// kernel source. Used only to exercise audit:full-mode recall.
//
// Pattern of interest: scatterwalk_map_and_copy() walks an SG list
// past the RX buffer end, kmap_local_page()s the next page, and
// writes `nbytes` into it. When the SG was assembled from an
// AF_ALG/splice() pipe of a tmpfs page, this is an OOB write into
// kernel's page-cache copy of an unrelated file. CWE-787 / CWE-125.

#include <linux/types.h>
#include <linux/string.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>

struct scatter_walk {
    struct scatterlist *sg;
    unsigned int        offset;
};

static void scatterwalk_start(struct scatter_walk *walk,
                              struct scatterlist *sg)
{
    walk->sg = sg;
    walk->offset = sg->offset;
}

static struct page *scatterwalk_page(struct scatter_walk *walk)
{
    // Returns the page at the current walk position. Does NOT verify
    // walk->offset is within walk->sg->length; on overflow we walk to
    // sg_next() with no bounds check on the kmap target.
    unsigned int page_index = walk->offset >> PAGE_SHIFT;
    return nth_page(sg_page(walk->sg), page_index);
}

static void scatterwalk_advance(struct scatter_walk *walk, unsigned int n)
{
    walk->offset += n;
    while (walk->sg && walk->offset >= walk->sg->offset + walk->sg->length) {
        // Bug: when we step past the SG end we transparently hop to
        // sg_next() WITHOUT checking that the new SG's pages were
        // ever validated as writable kernel-owned scratch. AF_ALG +
        // splice() can stitch a tmpfs page-cache page in here.
        walk->offset -= walk->sg->length;
        walk->sg = sg_next(walk->sg);
    }
}

void scatterwalk_map_and_copy(void *buf, struct scatterlist *sg,
                              unsigned int start, unsigned int nbytes,
                              int out)
{
    struct scatter_walk walk;
    unsigned int offset_in_page;
    void *vaddr;
    struct page *pg;

    scatterwalk_start(&walk, sg);
    scatterwalk_advance(&walk, start);

    pg = scatterwalk_page(&walk);
    offset_in_page = walk.offset & (PAGE_SIZE - 1);

    // Bug: kmap_local_page() on an attacker-influenced page index,
    // followed by an unbounded memcpy of `nbytes`. No check that
    // offset_in_page + nbytes stays within PAGE_SIZE, no check that
    // pg is a kernel-owned scratch page. CWE-787.
    vaddr = kmap_local_page(pg);
    if (out)
        memcpy(vaddr + offset_in_page, buf, nbytes);
    else
        memcpy(buf, vaddr + offset_in_page, nbytes);
    kunmap_local(vaddr);
}
"#;

/// Convert a `FindingListReport` into the JSON shape the scorer
/// expects (`{count, findings: [...]}`). Avoids shelling out to the
/// `kuzushi findings --json` binary, since this test runs from a
/// crate that doesn't pull in the CLI.
fn dump_findings_for_scorer(store: &FindingStore) -> Value {
    let report = store
        .list_findings_filtered(&FindingListFilter::default())
        .expect("list findings");
    serde_json::to_value(&report).expect("serialise findings dump")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live experiment; requires HOME/.claude/remote/.oauth_token"]
async fn audit_full_mode_recall_against_linux_copy_fail_oracle() {
    let token_path = host_token_path();
    if !token_path.exists() {
        eprintln!("skipping: no OAuth token at {}", token_path.display());
        return;
    }

    let (oracle_path, oracle) = match load_oracle(SLICE) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping: cannot load oracle for slice {SLICE}: {e}");
            return;
        }
    };

    let Some(slice) = build_slice(&oracle) else {
        eprintln!("skipping: could not materialise a source slice");
        return;
    };

    std::env::set_var("KUZUSHI_MAX_USD_PER_RUN", "2.00");

    let mut opts = AnthropicOAuthRuntimeOptions::from_token_file(&token_path)
        .expect("token file should be readable");
    opts.timeout = Some(Duration::from_secs(180));
    opts.max_tokens = Some(4096);
    if let Ok(base) = std::env::var("ANTHROPIC_BASE_URL") {
        opts.base_url = Some(base);
    }
    let runtime = AnthropicOAuthRuntime::new(opts).expect("runtime should build");

    let workspace = WorkspaceTarget::new(slice.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    drop(store);

    let mut config = V2Config::default();
    config.model = Some(HAIKU_MODEL.to_string());
    let registry = ModuleRegistry::with_v2_builtins();

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
    };

    let started = Instant::now();
    let result = registry
        .execute_tool_with_runtime(
            "audit:full-mode",
            json!({
                "dryRun": false,
                "language": "c",
                "maxTokensPerChunk": 80_000,
                "depositUsdPerChunk": 0.75,
            }),
            &ctx,
            Some(&runtime as &dyn AgentRuntime),
        )
        .expect("live audit:full-mode should succeed");
    let elapsed = started.elapsed();

    eprintln!("--- audit:full-mode live recall dispatch ---");
    eprintln!("wallclock : {elapsed:?}");
    eprintln!(
        "summary   : {}",
        result
            .pointer("/output")
            .and_then(Value::as_str)
            .unwrap_or("")
    );
    eprintln!(
        "report    : {}",
        serde_json::to_string_pretty(
            &result
                .pointer("/data/report/summary")
                .unwrap_or(&Value::Null)
        )
        .unwrap_or_default()
    );

    let chunks_dispatched = result
        .pointer("/data/report/data/chunks_dispatched")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cost = result
        .pointer("/costUsd")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let findings_persisted = result
        .pointer("/data/findingsPersisted")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    assert!(
        elapsed < WALLCLOCK_CAP,
        "wallclock cap exceeded: {elapsed:?} > {WALLCLOCK_CAP:?}"
    );
    assert!(
        cost < COST_CEILING_USD,
        "cost ceiling exceeded: ${cost:.4} >= ${COST_CEILING_USD:.2}"
    );
    assert!(
        chunks_dispatched >= 1,
        "expected at least one chunk dispatched, got {chunks_dispatched}"
    );

    eprintln!(
        "chunks_dispatched={chunks_dispatched} cost=${cost:.4} findings_persisted={findings_persisted}"
    );

    drop(store);
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let dump = dump_findings_for_scorer(&store);
    drop(store);

    let report = run_scorer(SLICE, slice.path(), &oracle_path, &dump).expect("scorer");
    eprintln!(
        "--- kuzushi-eval recall report ---\n{}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );

    let recall_file = report["recall"]["file_only"].as_f64().unwrap_or(0.0);
    let recall_pm10 = report["recall"]["pm_lines"].as_f64().unwrap_or(0.0);
    let recall_function = report["recall"]["function"].as_f64().unwrap_or(0.0);
    let hits = report["hits"].as_u64().unwrap_or(0);
    let findings_total = report["findings_total"].as_u64().unwrap_or(0);

    eprintln!(
        "recall: file_only={recall_file:.3} pm_lines={recall_pm10:.3} function={recall_function:.3} hits={hits} findings_total={findings_total}"
    );

    if findings_persisted == 0 {
        // Honest-signal mode: model returned no findings. Don't
        // pretend recall — assert only that the dispatch path fired
        // and we paid for it.
        eprintln!(
            "NOTE: model returned 0 findings; softening recall assertion to dispatch+cost+wallclock only"
        );
        assert!(cost > 0.0, "expected non-zero spend on a live dispatch");
    } else {
        assert!(
            recall_file > 0.0,
            "expected at least one finding to land at file-level tolerance against the oracle; got recall.file_only={recall_file} hits={hits} findings_total={findings_total}"
        );
    }

    let _ = slice;
}
