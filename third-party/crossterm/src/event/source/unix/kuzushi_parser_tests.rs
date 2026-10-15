use super::Parser;
use crate::event::InternalEvent;
use crate::event::{Event, KeyCode, KeyEvent, KeyModifiers};

fn key(code: KeyCode) -> InternalEvent {
    InternalEvent::Event(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)))
}

fn decode(chunks: &[&[u8]]) -> Vec<InternalEvent> {
    let mut parser = Parser::default();
    for (index, chunk) in chunks.iter().enumerate() {
        parser.advance(chunk, index + 1 < chunks.len());
    }
    parser.collect()
}

#[test]
fn coalesced_escape_and_navigation_preserve_both_keys_at_every_split() {
    for (bytes, code) in [
        (b"\x1b\x1b[4~".as_slice(), KeyCode::End),
        (b"\x1b\x1b[A".as_slice(), KeyCode::Up),
        (b"\x1b\x1bOP".as_slice(), KeyCode::F(1)),
    ] {
        for split in 1..bytes.len() {
            assert_eq!(
                decode(&[&bytes[..split], &bytes[split..]]),
                vec![key(KeyCode::Esc), key(code)]
            );
        }
        assert_eq!(decode(&[bytes]), vec![key(KeyCode::Esc), key(code)]);
    }
}

#[test]
fn repeated_escape_presses_are_independent_events() {
    assert_eq!(
        decode(&[b"\x1b\x1b\x1b"]),
        vec![key(KeyCode::Esc), key(KeyCode::Esc), key(KeyCode::Esc)]
    );
}

#[test]
fn bracketed_paste_preserves_literal_escape_pairs_and_sequence_text() {
    let payload = "α\x1b\x1b[4~\n[4~β";
    let bytes = format!("\x1b[200~{payload}\x1b[201~");
    for split in 1..bytes.len() {
        assert_eq!(
            decode(&[&bytes.as_bytes()[..split], &bytes.as_bytes()[split..]]),
            vec![InternalEvent::Event(Event::Paste(payload.into()))]
        );
    }
}

#[test]
fn plain_sequence_text_and_alt_characters_remain_unchanged() {
    let expected = vec![
        key(KeyCode::Char('[')),
        key(KeyCode::Char('4')),
        key(KeyCode::Char('~')),
    ];
    assert_eq!(decode(&[b"[4~"]), expected);
    assert_eq!(
        decode(&[b"\x1bx"]),
        vec![InternalEvent::Event(Event::Key(KeyEvent::new(
            KeyCode::Char('x'),
            KeyModifiers::ALT
        )))]
    );
}

#[test]
fn encoded_modifiers_and_split_unicode_remain_unchanged() {
    assert_eq!(
        decode(&[b"\x1b[1;3F"]),
        vec![InternalEvent::Event(Event::Key(KeyEvent::new(
            KeyCode::End,
            KeyModifiers::ALT
        )))]
    );
    let bytes = "αβ".as_bytes();
    for split in 1..bytes.len() {
        assert_eq!(
            decode(&[&bytes[..split], &bytes[split..]]),
            vec![key(KeyCode::Char('α')), key(KeyCode::Char('β'))]
        );
    }
}
