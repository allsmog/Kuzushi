use super::super::bridge_process::run_next_step_bridge_observed;
use super::super::{ResponseTextEvent, ResponseTextObserver};
use super::*;

const STREAM_PREFIX: &str = r#"
import json, sys, time, pathlib
request = json.load(sys.stdin)
assert request['responseEvents'] == 'text-v1'
def frame(value):
    print(chr(30) + json.dumps(value), flush=True)
frame({'type':'reset'})
frame({'type':'text','text':'partial 東京'})
"#;

#[test]
fn bridge_stream_callback_unblocks_child_before_terminal_output() {
    let dir = tempdir().unwrap();
    let gate = dir.path().join("delta-observed");
    let callback_gate = gate.clone();
    let observer = ResponseTextObserver::new(move |event| {
        if matches!(event, ResponseTextEvent::Delta(_)) {
            fs::write(&callback_gate, "seen").unwrap();
        }
    });
    let script = format!("{STREAM_PREFIX}\ndeadline = time.monotonic() + 4\nwhile not pathlib.Path(sys.argv[1]).exists():\n    assert time.monotonic() < deadline\n    time.sleep(0.01)\nframe({{'type':'result','result':{{'ok':True,'step':'final','text':'authoritative','output_tokens':7}}}})\n");
    let command = vec![
        "python3".into(),
        "-c".into(),
        script,
        gate.display().to_string(),
    ];
    let result =
        run_next_step_bridge_observed(&command, &test_next_step_request(), None, Some(&observer))
            .unwrap();
    assert_eq!(result.text.as_deref(), Some("authoritative"));
    assert_eq!(result.output_tokens, Some(7));
    assert!(gate.is_file());
}

#[test]
fn bridge_stream_cancellation_stops_provider_process_after_partial_text() {
    let cancel = kuzushi_core::ScanCancellation::default();
    let signal = cancel.clone();
    let observer = ResponseTextObserver::new(move |event| {
        if matches!(event, ResponseTextEvent::Delta(_)) {
            signal.cancel();
        }
    });
    let script = format!("{STREAM_PREFIX}\nwhile True: time.sleep(0.01)\n");
    let command = vec!["python3".into(), "-c".into(), script];
    let started = Instant::now();
    let error = run_next_step_bridge_observed(
        &command,
        &test_next_step_request(),
        Some(&cancel),
        Some(&observer),
    )
    .unwrap_err();
    assert!(error.to_string().contains("cancel"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(5));
}
