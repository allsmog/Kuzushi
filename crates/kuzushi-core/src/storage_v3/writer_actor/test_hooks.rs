use crate::event_log::EventEnvelope;
use std::time::Duration;

const PAUSE_KIND: &str = "KUZUSHI_TEST_STORAGE_PAUSE_EVENT_KIND";
const PAUSE_MARKER: &str = "KUZUSHI_TEST_STORAGE_PAUSE_MARKER";

pub(super) fn after_event_append(event: &EventEnvelope) {
    let Ok(kind) = std::env::var(PAUSE_KIND) else {
        return;
    };
    if kind != event.event_kind.as_str() {
        return;
    }
    let Some(marker) = std::env::var_os(PAUSE_MARKER) else {
        return;
    };
    std::fs::write(marker, event.seq.to_string())
        .expect("storage fault hook must publish its append marker");
    loop {
        std::thread::sleep(Duration::from_millis(25));
    }
}
