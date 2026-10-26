use crossterm::SynchronizedUpdate;
use std::io::{self, Write};

pub(super) fn paint_synchronized_frame<W: Write>(
    output: &mut W,
    paint: impl FnOnce(&mut W) -> io::Result<()>,
) -> io::Result<()> {
    output.sync_update(paint)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_paint_is_inside_one_synchronized_update() {
        let mut bytes = Vec::new();
        paint_synchronized_frame(&mut bytes, |output| output.write_all(b"frame")).unwrap();
        assert_eq!(bytes, b"\x1b[?2026hframe\x1b[?2026l");
    }

    #[test]
    fn failed_paint_closes_the_update_and_retains_its_error() {
        let mut bytes = Vec::new();
        let error = paint_synchronized_frame(&mut bytes, |output| {
            output.write_all(b"partial")?;
            Err(io::Error::other("paint failed"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "paint failed");
        assert_eq!(bytes, b"\x1b[?2026hpartial\x1b[?2026l");
    }
}
