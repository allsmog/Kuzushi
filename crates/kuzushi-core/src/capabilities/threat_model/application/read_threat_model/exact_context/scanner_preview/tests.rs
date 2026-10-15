use super::*;

#[test]
fn preview_is_the_existing_execution_digest_with_an_exact_hash() {
    let document = json!({"systemContext":"Full document only", "threats":[{"title":"Owned source review","severity":"low"}],"dfd":{"nodes":[{"id":"owned","name":"Owned application"}]}});
    let preview = build(&document);
    assert_eq!(preview["schemaVersion"], 1);
    let expected =
        crate::capabilities::agentic_sast::render_threat_model_digest(&document).unwrap();
    assert_eq!(preview["text"], expected);
    assert_eq!(
        preview["sha256"],
        crate::options::prompt_content_sha256(&expected)
    );
    assert!(!expected.contains("Full document only"));
}

#[test]
fn item_and_unicode_lesson_omissions_are_disclosed_without_rewriting_the_digest() {
    let lesson = format!("{} tail omitted", "界".repeat(2048));
    let document = json!({"threats":vec![json!({"title":"Owned observation"});13],"reviewedLessons":[{"id":"owned","revision":1,"content":{"title":"Owned lesson","text":lesson,"applicability":"Review only","limitations":"Synthetic owned example"}}]});
    let preview = build(&document);
    let notices = preview["omissions"].to_string();
    assert!(notices.contains("first 12 of 13"));
    assert!(notices.contains("first 2048 of 2061 characters"));
    let text = preview["text"].as_str().unwrap();
    assert!(text.contains(&"界".repeat(2048)));
    assert!(!text.contains("tail omitted"));
    assert_eq!(
        preview["text"],
        crate::capabilities::agentic_sast::render_threat_model_digest(&document).unwrap()
    );
}

#[test]
fn an_empty_digest_is_explicit_and_never_filled_from_unselected_fields() {
    let preview = build(&json!({"systemContext":"Saved context without digest sections"}));
    assert!(preview["text"].is_null());
    assert!(preview["sha256"].is_null());
    assert_eq!(preview["omissions"], json!([]));
}
