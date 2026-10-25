use super::*;
use crate::app::ContextComparisonCursor;
use kuzushi_core::capabilities::threat_model::{
    context_document_differences, context_text_differences,
};
use kuzushi_core::{ThreatModelId, ThreatModelRef, ThreatModelRevisionId};
use serde_json::json;

fn reference(digest: char) -> ThreatModelRef {
    ThreatModelRef {
        model_id: ThreatModelId::new(),
        revision_id: ThreatModelRevisionId::new(),
        sha256: format!("sha256:{}", digest.to_string().repeat(64)),
    }
}

fn fixture() -> StudyContextComparison {
    let before = json!({"systemContext":"Before architecture", "dfd":{"nodes":[{"id":"store","type":"process","trustZone":"internal","sourceRefs":[" app /lib.py:2"]}],"flows":[],"trustBoundaries":[]}, "openQuestions":["Before question"], "targetGit":{"sha":"aaaaaaaa","dirty":false},"metadata":{"explicit":null}});
    let mut after = before.clone();
    after["systemContext"] = json!("After architecture");
    after["dfd"]["nodes"][0]["type"] = json!("data-store");
    after["dfd"]["nodes"][0]["sourceRefs"] = json!(["app/lib.py:3"]);
    after["targetGit"]["sha"] = json!("bbbbbbbb");
    after["openQuestions"] = json!(["After question"]);
    after["metadata"] = json!({"added":null});
    StudyContextComparison {
        target: "/owned/fixture".into(),
        parent: reference('a'),
        candidate: reference('b'),
        differences: Some(context_text_differences(&before, &after)),
        structure: Some(context_document_differences(&before, &after)),
        error: None,
        view: ContextComparisonView::Text,
        cursors: [ContextComparisonCursor::default(); 4],
    }
}

#[test]
fn plain_comparison_is_exhaustive_across_views_independent_of_selection() {
    let mut context = fixture();
    context.view = ContextComparisonView::Other;
    context.cursors[3].scroll = usize::MAX;
    let plain = all_lines(&context, 120).join("\n");
    for expected in [
        "Before architecture",
        "After architecture",
        "process",
        "data-store",
        " app /lib.py:2",
        "app/lib.py:3",
        "aaaaaaaa",
        "bbbbbbbb",
        "Before question",
        "After question",
        "(not present)",
        "null",
        "Saved source claims differ",
        "finding fixes",
    ] {
        assert!(plain.contains(expected), "missing {expected}: {plain}");
    }
    assert!(plain.contains(&context.parent.sha256));
    assert!(plain.contains(&context.candidate.sha256));
}

#[test]
fn comparison_layout_preserves_controls_and_reading_room_at_six_sizes() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let area = crate::ui_view_models::study_config::study_config_area(width, height);
        let layout = layout(area);
        assert!(layout.detail.height >= 6);
        assert_eq!(layout.controls.height, 2);
        assert!(layout.detail.bottom() <= layout.controls.y);
        assert!(layout.detail.right() <= area.right());
        assert!(layout.tabs.bottom() <= layout.list.y);
        assert!(!layout.list.intersects(layout.detail));
    }
}

#[test]
fn duplicate_id_comparison_discloses_ambiguous_matching_and_both_positions() {
    let before =
        json!({"dfd":{"nodes":[{"id":"x","type":"process"},{"id":"x","type":"data-store"}]}});
    let after = json!({"dfd":{"nodes":[{"id":"x","type":"external-entity"}]}});
    let mut context = fixture();
    context.structure = Some(context_document_differences(&before, &after));
    let plain = all_lines(&context, 120).join("\n");
    assert!(plain.contains("Duplicate ID; compared by position. Identity is ambiguous."));
    assert!(plain.contains("/dfd/nodes/0/type"));
    assert!(plain.contains("/dfd/nodes/1"));
    assert!(plain.contains("(not recorded)"));
}

#[test]
fn absent_ids_and_pointers_are_labeled_without_looking_like_null_values() {
    let context = fixture();
    let entry = entries(&context, ContextComparisonView::Other).remove(0);
    assert!(!title(&entry).contains("field null"));
    let lines = content::lines(&context, &entry);
    assert!(lines.contains(&"Parent pointer: (not present)".to_owned()));
    assert!(lines.contains(&"null".to_owned()));
}

#[test]
fn conflicting_recorded_revisions_are_disclosed_without_choosing_one() {
    let mut context = fixture();
    let claims = &mut context.structure.as_mut().unwrap().source_claims;
    claims
        .before
        .insert("/provenance/revision".into(), json!("cccccccc"));
    let plain = all_lines(&context, 120).join("\n");
    assert!(plain.contains("Parent recorded revision fields disagree"));
    assert!(plain.contains("no source identity is selected automatically"));
    assert!(plain.contains("aaaaaaaa") && plain.contains("cccccccc"));
}

#[test]
fn a_comparison_without_a_stored_result_reads_as_pending_in_every_view() {
    for drop_structure in [false, true] {
        let mut context = fixture();
        context.differences = None;
        if drop_structure {
            context.structure = None;
        }
        for view in ContextComparisonView::ALL {
            context.view = view;
            assert!(entries(&context, view).is_empty(), "{view:?}");
            assert!(
                selected_lines(&context, 80)
                    .join(" ")
                    .contains("Reading the authenticated parent"),
                "{view:?}"
            );
        }
        assert!(all_lines(&context, 80)
            .join(" ")
            .contains("Reading the authenticated parent"));
    }
}

#[test]
fn the_source_entry_carries_the_claims_of_the_structure_it_came_from() {
    let context = fixture();
    let claims = entries(&context, ContextComparisonView::Source)
        .into_iter()
        .find_map(|entry| match entry {
            ComparisonEntry::Source(claims) => Some(claims),
            _ => None,
        })
        .expect("the source view lists the saved identities");
    assert_eq!(claims, &context.structure.as_ref().unwrap().source_claims);
    assert!(content::lines(&context, &ComparisonEntry::Source(claims))
        .join(" ")
        .contains("Saved source claims differ"));
}
