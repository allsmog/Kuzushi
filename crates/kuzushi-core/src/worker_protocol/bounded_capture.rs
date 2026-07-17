use super::{KwpError, KWP_MAX_MESSAGE_BYTES};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

pub(super) const FUZZ_STDOUT_LIMIT: usize = KWP_MAX_MESSAGE_BYTES;
pub(super) const FUZZ_STDERR_LIMIT: usize = 64 * 1024;

pub(super) struct BoundedCapture {
    resource: &'static str,
    overflowed: Arc<AtomicBool>,
    reader: JoinHandle<std::io::Result<Vec<u8>>>,
}

impl BoundedCapture {
    pub(super) fn spawn(
        reader: impl Read + Send + 'static,
        limit: usize,
        resource: &'static str,
    ) -> Self {
        let overflowed = Arc::new(AtomicBool::new(false));
        let reader_overflowed = Arc::clone(&overflowed);
        let reader = thread::spawn(move || drain_bounded(reader, limit, &reader_overflowed));
        Self {
            resource,
            overflowed,
            reader,
        }
    }

    pub(super) fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::Acquire)
    }

    pub(super) fn finish(self) -> Result<Vec<u8>, KwpError> {
        let Self {
            resource,
            overflowed,
            reader,
        } = self;
        let bytes = reader
            .join()
            .map_err(|_| KwpError::Internal(format!("{resource} reader panicked")))?
            .map_err(|error| KwpError::Internal(format!("could not read {resource}: {error}")))?;
        if overflowed.load(Ordering::Acquire) {
            Err(KwpError::quota(resource))
        } else {
            Ok(bytes)
        }
    }
}

fn drain_bounded(
    mut reader: impl Read,
    limit: usize,
    overflowed: &AtomicBool,
) -> std::io::Result<Vec<u8>> {
    let mut retained = Vec::with_capacity(limit.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(retained);
        }
        retain_up_to_limit(&mut retained, &buffer[..read], limit, overflowed);
    }
}

fn retain_up_to_limit(retained: &mut Vec<u8>, bytes: &[u8], limit: usize, overflowed: &AtomicBool) {
    let available = limit.saturating_sub(retained.len());
    let retained_len = available.min(bytes.len());
    retained.extend_from_slice(&bytes[..retained_len]);
    if retained_len < bytes.len() {
        overflowed.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn boundary_succeeds_and_limit_plus_one_reports_stable_quota() {
        assert_eq!(
            BoundedCapture::spawn(Cursor::new(vec![b'x'; 8]), 8, "fixture.bytes")
                .finish()
                .unwrap(),
            vec![b'x'; 8]
        );

        assert_eq!(
            BoundedCapture::spawn(Cursor::new(vec![b'x'; 9]), 8, "fixture.bytes")
                .finish()
                .unwrap_err(),
            KwpError::quota("fixture.bytes")
        );
    }

    #[test]
    fn overflow_is_signaled_while_the_reader_still_drains_to_eof() {
        let capture = BoundedCapture::spawn(Cursor::new(vec![b'x'; 32 * 1024]), 16, "fixture");
        let error = capture.finish().unwrap_err();

        assert_eq!(error, KwpError::quota("fixture"));
    }
}
