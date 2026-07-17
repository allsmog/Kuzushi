use super::*;

pub(super) fn spawn_hydration_worker(
    generation: u64,
    target: PathBuf,
    keys: Vec<ViewHydrationKey>,
    reader: Arc<dyn ViewArtifactReader>,
    cancellation: ViewHydrationCancellation,
    tx: SyncSender<ViewHydrationMessage>,
    wake: Option<TerminalLoopWake>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        hydrate_keys(
            generation,
            &target,
            keys,
            reader.as_ref(),
            &cancellation,
            &tx,
            wake.as_ref(),
        );
    })
}

fn hydrate_keys(
    generation: u64,
    target: &Path,
    keys: Vec<ViewHydrationKey>,
    reader: &dyn ViewArtifactReader,
    cancellation: &ViewHydrationCancellation,
    tx: &SyncSender<ViewHydrationMessage>,
    wake: Option<&TerminalLoopWake>,
) {
    for key in keys {
        if !hydrate_key(generation, target, key, reader, cancellation, tx, wake) {
            return;
        }
    }
}

fn hydrate_key(
    generation: u64,
    target: &Path,
    key: ViewHydrationKey,
    reader: &dyn ViewArtifactReader,
    cancellation: &ViewHydrationCancellation,
    tx: &SyncSender<ViewHydrationMessage>,
    wake: Option<&TerminalLoopWake>,
) -> bool {
    if cancellation.is_canceled() {
        return false;
    }
    let Some(message) = hydration_message(generation, target, key, reader, cancellation) else {
        return false;
    };
    if tx.send(message).is_err() {
        return false;
    }
    if let Some(wake) = wake {
        wake.notify();
    }
    true
}

fn hydration_message(
    generation: u64,
    target: &Path,
    key: ViewHydrationKey,
    reader: &dyn ViewArtifactReader,
    cancellation: &ViewHydrationCancellation,
) -> Option<ViewHydrationMessage> {
    match caught_read(reader, target, &key, cancellation) {
        Ok(Some(value)) => Some(ViewHydrationMessage::Result {
            generation,
            result: ViewHydrationResult {
                target: target.to_path_buf(),
                key,
                value,
            },
        }),
        Ok(None) => None,
        Err(()) => Some(ViewHydrationMessage::Failed {
            generation,
            target: target.to_path_buf(),
            key,
        }),
    }
}
