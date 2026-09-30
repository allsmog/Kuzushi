use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};
use std::sync::{mpsc, Arc};
use std::thread;

fn terminal(event: TermEvent) -> QueuedEvent {
    Ok(TerminalLoopEvent::Terminal(event))
}

fn key(character: char) -> QueuedEvent {
    terminal(TermEvent::Key(KeyEvent::new(
        KeyCode::Char(character),
        KeyModifiers::NONE,
    )))
}

#[test]
fn terminal_queue_flood_coalesces_replaceable_states_to_the_latest_values() {
    let queue = TerminalEventQueue::default();
    for value in 0..25_000_u16 {
        assert!(queue.send(terminal(TermEvent::Resize {
            columns: value,
            rows: 24
        })));
        assert!(queue.send(terminal(TermEvent::Focus {
            focused: value % 2 == 0
        })));
        assert!(queue.send(terminal(TermEvent::Mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: value,
            row: 1,
            modifiers: KeyModifiers::NONE,
        }))));
    }
    let stats = queue.stats();
    assert_eq!(stats.queued, 3);
    assert_eq!(stats.peak, 3);
    assert_eq!(stats.coalesced, 74_997);
    assert!(stats.bytes <= INPUT_BYTE_LIMIT);
    assert!(matches!(
        queue.try_recv(),
        Ok(Ok(TerminalLoopEvent::Terminal(TermEvent::Resize {
            columns: 24_999,
            ..
        })))
    ));
    assert!(matches!(
        queue.try_recv(),
        Ok(Ok(TerminalLoopEvent::Terminal(TermEvent::Focus {
            focused: false
        })))
    ));
    assert!(matches!(
        queue.try_recv(),
        Ok(Ok(TerminalLoopEvent::Terminal(TermEvent::Mouse(
            MouseEvent { column: 24_999, .. }
        ))))
    ));
}

#[test]
fn terminal_queue_coalescing_cannot_move_state_across_ordered_input() {
    let queue = TerminalEventQueue::default();
    queue.send(terminal(TermEvent::Resize {
        columns: 80,
        rows: 24,
    }));
    queue.send(key('a'));
    queue.send(terminal(TermEvent::Resize {
        columns: 100,
        rows: 24,
    }));
    queue.send(terminal(TermEvent::Resize {
        columns: 120,
        rows: 24,
    }));
    assert!(matches!(
        queue.try_recv(),
        Ok(Ok(TerminalLoopEvent::Terminal(TermEvent::Resize {
            columns: 80,
            ..
        })))
    ));
    assert!(matches!(
        queue.try_recv(),
        Ok(Ok(TerminalLoopEvent::Terminal(TermEvent::Key(KeyEvent {
            code: KeyCode::Char('a'),
            ..
        }))))
    ));
    assert!(matches!(
        queue.try_recv(),
        Ok(Ok(TerminalLoopEvent::Terminal(TermEvent::Resize {
            columns: 120,
            ..
        })))
    ));
}

#[test]
fn saturated_terminal_queue_preserves_keys_and_paste_and_keeps_wakes_responsive() {
    let queue = Arc::new(TerminalEventQueue::default());
    for _ in 0..INPUT_EVENT_LIMIT {
        assert!(queue.send(key('a')));
    }
    let producer_queue = queue.clone();
    let (started, ready) = mpsc::sync_channel(0);
    let (completed, completion) = mpsc::sync_channel(1);
    let paste = "exact\nβ\r\n終\n";
    let producer = thread::spawn(move || {
        started.send(()).unwrap();
        let accepted = producer_queue.send(terminal(TermEvent::Paste(paste.into())));
        assert!(producer_queue.send(key('z')));
        completed.send(accepted).unwrap();
    });
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(
        completion.recv_timeout(Duration::from_millis(25)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert!(queue.notify());
    assert!(matches!(queue.try_recv(), Ok(Ok(TerminalLoopEvent::Wake))));
    for _ in 0..INPUT_EVENT_LIMIT {
        assert!(matches!(
            queue.try_recv(),
            Ok(Ok(TerminalLoopEvent::Terminal(TermEvent::Key(KeyEvent {
                code: KeyCode::Char('a'),
                ..
            }))))
        ));
    }
    match queue.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(TerminalLoopEvent::Terminal(TermEvent::Paste(text)))) => assert_eq!(text, paste),
        _ => panic!("ordered paste missing"),
    }
    assert!(matches!(
        queue.recv_timeout(Duration::from_secs(2)),
        Ok(Ok(TerminalLoopEvent::Terminal(TermEvent::Key(KeyEvent {
            code: KeyCode::Char('z'),
            ..
        }))))
    ));
    assert!(completion.recv_timeout(Duration::from_secs(2)).unwrap());
    producer.join().unwrap();
    assert!(queue.stats().blocked > 0);
    assert_eq!(queue.stats().peak, INPUT_EVENT_LIMIT);
}

#[test]
fn terminal_queue_enforces_aggregate_bytes_and_rejects_oversized_paste_explicitly() {
    let mut state = QueueState::default();
    for _ in 0..3 {
        assert!(state
            .insert(terminal(TermEvent::Paste("x".repeat(PASTE_BYTE_LIMIT))))
            .is_ok());
    }
    assert!(state
        .insert(terminal(TermEvent::Paste("x".repeat(PASTE_BYTE_LIMIT))))
        .is_err());
    assert!(state.stats.bytes <= INPUT_BYTE_LIMIT);
    assert_eq!(state.stats.queued, 3);
    let queue = TerminalEventQueue::default();
    assert!(queue.send(terminal(TermEvent::Paste("x".repeat(PASTE_BYTE_LIMIT + 1)))));
    match queue.try_recv() {
        Ok(Err(error)) => assert!(error.contains("paste was not accepted")),
        _ => panic!("oversized paste must be rejected visibly"),
    }
}

#[test]
fn closing_terminal_queue_releases_a_blocked_reader() {
    let queue = Arc::new(TerminalEventQueue::default());
    for _ in 0..INPUT_EVENT_LIMIT {
        assert!(queue.send(key('a')));
    }
    let producer_queue = queue.clone();
    let (send, receive) = mpsc::sync_channel(1);
    let producer = thread::spawn(move || send.send(producer_queue.send(key('b'))).unwrap());
    queue.close();
    assert!(!receive.recv_timeout(Duration::from_secs(2)).unwrap());
    producer.join().unwrap();
}
