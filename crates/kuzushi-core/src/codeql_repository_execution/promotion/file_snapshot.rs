use anyhow::Result;
use std::fs;
use std::io::Read;
use std::path::Path;

pub(super) fn stream_exact_file<F>(
    source: &mut fs::File,
    expected: u64,
    mut consume: F,
) -> Result<()>
where
    F: FnMut(&[u8]) -> std::io::Result<()>,
{
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = read_next_chunk(source, expected, total, &mut buffer)?;
        if count == 0 {
            break;
        }
        consume(&buffer[..count])?;
        total += count as u64;
    }
    anyhow::ensure!(
        total == expected,
        "CodeQL database file shrank while reading"
    );
    Ok(())
}

fn read_next_chunk(
    source: &mut fs::File,
    expected: u64,
    total: u64,
    buffer: &mut [u8],
) -> Result<usize> {
    let remaining = expected.saturating_sub(total);
    let limit = (remaining.saturating_add(1)).min(buffer.len() as u64) as usize;
    let count = source.read(&mut buffer[..limit])?;
    anyhow::ensure!(
        count as u64 <= remaining,
        "CodeQL database file grew while reading"
    );
    Ok(count)
}

pub(super) fn verify_source_unchanged(
    source: &fs::File,
    before: &fs::Metadata,
    path: &Path,
) -> Result<()> {
    let after = source.metadata()?;
    let same_modified = before.modified().ok() == after.modified().ok();
    anyhow::ensure!(
        before.len() == after.len() && same_modified,
        "CodeQL database file changed while copying: {}",
        path.display()
    );
    Ok(())
}
