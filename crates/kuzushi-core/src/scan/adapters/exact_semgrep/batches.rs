//! Pack literal file arguments without changing membership or exceeding process limits.
use super::*;

pub(in crate::scan) const MAX_FILES_PER_PROCESS: usize = 1024;
pub(in crate::scan) const MAX_ARGUMENT_BYTES: usize = 12 * 1024;

pub(super) struct FileBatches<'a> {
    remaining: &'a [String],
    fixed_bytes: usize,
}

impl<'a> FileBatches<'a> {
    pub(super) fn new(command: &Command, files: &'a [String]) -> Result<Self> {
        let fixed_bytes = std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(|value| value.as_encoded_bytes().len().saturating_add(1))
            .fold(0usize, usize::saturating_add);
        anyhow::ensure!(
            fixed_bytes < MAX_ARGUMENT_BYTES,
            "Semgrep fixed process arguments exceed the {MAX_ARGUMENT_BYTES}-byte allowance"
        );
        Ok(Self {
            remaining: files,
            fixed_bytes,
        })
    }

    fn next_batch_len(&self) -> usize {
        let mut available = MAX_ARGUMENT_BYTES - self.fixed_bytes;
        self.remaining
            .iter()
            .take(MAX_FILES_PER_PROCESS)
            .take_while(|file| {
                let bytes = file.len().saturating_add(1);
                if bytes > available {
                    return false;
                }
                available -= bytes;
                true
            })
            .count()
    }
}

impl<'a> Iterator for FileBatches<'a> {
    type Item = Result<&'a [String]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let count = self.next_batch_len();
        if count == 0 {
            self.remaining = &[];
            return Some(Err(anyhow::anyhow!("A selected file cannot fit Semgrep's {MAX_ARGUMENT_BYTES}-byte process argument allowance")));
        }
        let (batch, remaining) = self.remaining.split_at(count);
        self.remaining = remaining;
        Some(Ok(batch))
    }
}

#[cfg(test)]
mod tests;
