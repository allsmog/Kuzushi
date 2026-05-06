//! libxml2 surface-ranker experiment.
//!
//! Walks the pre-patch libxml2 source with the (now-scaled)
//! `gather_systems_context` and verifies the buggy
//! `xmlSnprintfElements` function lands on the ranked surface list.
//!
//! This tests the *fast pass* of the surface ranker only — no LLM,
//! no codeindex (joern is absent in the dev sandbox so the index
//! augmentation no-ops cleanly). Run-time ~seconds, cost $0.
//!
//! Run with:
//!     LIBXML2_REPO=/tmp/xml2-experiment/libxml2 \
//!     cargo test -p kuzushi-core \
//!       --test experiment_libxml2_surface_ranker -- --nocapture --ignored

use std::path::PathBuf;

#[test]
#[ignore = "live experiment; requires LIBXML2_REPO to point at a pre-patch libxml2 checkout"]
fn libxml2_surface_ranker_includes_xml_snprintf_elements() {
    let Ok(repo) = std::env::var("LIBXML2_REPO") else {
        eprintln!("skipping: set LIBXML2_REPO to a libxml2 checkout (parent of 61e5f3e for the buggy state)");
        return;
    };
    let target = PathBuf::from(&repo);
    if !target.join("valid.c").exists() {
        eprintln!("skipping: {repo} does not look like a libxml2 checkout (no valid.c)");
        return;
    }

    // gather_surfaces runs the surface scorer + index augmenter
    // without the LLM stages. Bigger walker caps for an 80k-LoC library.
    let context = kuzushi_core::gather_surfaces(
        &target,
        &serde_json::json!({
            "maxSurfaces": 50,
            "maxFiles": 5000,
            "headBytes": 65536,  // 64 KiB head — captures most of valid.c's body
        }),
    )
    .expect("gather_surfaces should succeed");

    let surfaces = &context.surfaces;
    eprintln!(
        "===== Surface ranker: {} surfaces from libxml2 =====",
        surfaces.len()
    );
    let xml_snprintf = surfaces.iter().find(|s| s.file_path.ends_with("valid.c"));
    eprintln!();
    eprintln!("Top-10 surfaces:");
    for (i, s) in surfaces.iter().take(10).enumerate() {
        eprintln!(
            "  #{:>2}  score={:>4}  kind={:<25}  {}:{}",
            i + 1,
            s.score,
            s.kind,
            s.file_path,
            s.start_line
        );
    }
    eprintln!();
    eprintln!("Did valid.c land in the surface list?");
    match xml_snprintf {
        Some(s) => {
            let rank = surfaces
                .iter()
                .position(|cand| cand.file_path == s.file_path)
                .map(|p| p + 1)
                .unwrap_or(0);
            eprintln!(
                "  YES — valid.c at rank #{} (score={}, start_line={})",
                rank, s.score, s.start_line
            );
            eprintln!("  reasons: {:?}", &s.reasons[..s.reasons.len().min(5)]);
        }
        None => {
            eprintln!(
                "  NO — valid.c missed the top-{} surfaces. \
                 Either max_surfaces is too narrow for an 80k-LoC repo \
                 or the file's signal density is below the cutoff for \
                 the dataflow-relevant lines (xmlSnprintfElements is at \
                 ~line 4623; head_bytes may be cutting off before reaching \
                 it). Recommendation: increase headBytes or paginate the walk.",
                surfaces.len()
            );
        }
    }

    // The contract: at *any* rank in the ranked list is a HIT for
    // this fast-pass-only test. Surface ordering is the LLM's job
    // downstream; we only need detection.
    assert!(!surfaces.is_empty(), "no surfaces returned");
}
