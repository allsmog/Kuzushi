use super::*;
use std::io::Cursor;
use std::sync::{Arc, Mutex};

fn decode(bytes: &[u8], limit: usize) -> (Result<Vec<u8>>, Vec<ResponseTextEvent>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let saved = events.clone();
    let observer = ResponseTextObserver::new(move |event| saved.lock().unwrap().push(event));
    let result = read_response_frames(&mut Cursor::new(bytes), limit, &observer);
    let events = events.lock().unwrap().clone();
    (result, events)
}

#[test]
fn response_frames_reset_preview_and_return_only_authoritative_result() {
    let data = b"\x1e{\"type\":\"reset\"}\n\x1e{\"type\":\"text\",\"text\":\"first\"}\n\x1e{\"type\":\"reset\"}\n\x1e{\"type\":\"text\",\"text\":\"retry\"}\n\x1e{\"type\":\"result\",\"result\":{\"ok\":true,\"text\":\"final\"}}\n";
    let (result, events) = decode(data, 4096);
    let value: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(value["text"], "final");
    assert_eq!(
        events,
        vec![
            ResponseTextEvent::Reset,
            ResponseTextEvent::Delta("first".into()),
            ResponseTextEvent::Reset,
            ResponseTextEvent::Delta("retry".into())
        ]
    );
}

#[test]
fn response_frames_accept_legacy_json_without_inventing_progress() {
    let data = b"  {\n \"ok\": true\n}";
    let (result, events) = decode(data, 128);
    assert_eq!(result.unwrap(), data);
    assert!(events.is_empty());
}

#[test]
fn response_frames_fail_closed_on_truncation_order_shape_and_limits() {
    for data in [
        "\x1e{\"type\":\"reset\"}\n",
        "\x1e{\"type\":\"text\",\"text\":\"PRIVATE_SOURCE\"}\n",
        "\x1e{\"type\":\"result\",\"result\":{}}",
        "\x1e{\"type\":\"result\",\"result\":{}}\n\x1e{\"type\":\"reset\"}\n",
        "\x1e{\"type\":\"result\",\"result\":[]}\n",
        "\x1ePRIVATE_SOURCE\n",
    ] {
        let error = decode(data.as_bytes(), 4096).0.unwrap_err().to_string();
        assert!(!error.contains("PRIVATE_SOURCE"));
    }
    assert!(decode(b"123456", 5).0.is_err());
    assert!(decode(b"\x1e{\"type\":\"reset\"}\n", 5).0.is_err());
    let data = format!(
        "\x1e{{\"type\":\"reset\"}}\n\x1e{{\"type\":\"text\",\"text\":\"{}\"}}\n",
        "x".repeat(65_537)
    );
    assert!(decode(data.as_bytes(), 100_000).0.is_err());
}

#[test]
fn response_debug_exposes_only_byte_count() {
    assert!(
        !format!("{:?}", ResponseTextEvent::Delta("PRIVATE_SOURCE".into()))
            .contains("PRIVATE_SOURCE")
    );
}
