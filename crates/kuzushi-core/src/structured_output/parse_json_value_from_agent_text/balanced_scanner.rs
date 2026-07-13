use super::{JsonExtractionStrategy, MAX_STRUCTURED_RESPONSE_BYTES};
use std::collections::VecDeque;

pub(crate) const MAX_BALANCED_CANDIDATES: usize = 64;
pub(crate) const MAX_BALANCED_CANDIDATE_BYTES: usize = MAX_STRUCTURED_RESPONSE_BYTES;

pub(super) struct BalancedJsonCandidate<'a> {
    pub(super) strategy: JsonExtractionStrategy,
    pub(super) slice: &'a str,
}

pub(super) struct BalancedJsonScan<'a> {
    pub(super) candidates: Vec<BalancedJsonCandidate<'a>>,
    #[cfg(test)]
    pub(super) stats: BalancedJsonScanStats,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BalancedJsonScanStats {
    pub(crate) inspected_bytes: usize,
    pub(crate) completed_outer_spans: usize,
    pub(crate) retained_spans: usize,
    pub(crate) retained_bytes: usize,
    pub(crate) max_stack_depth: usize,
}

pub(super) fn scan_balanced_json(text: &str) -> BalancedJsonScan<'_> {
    let mut scanner = BalancedScanner::new(text);
    scanner.scan();
    scanner.finish()
}

struct BalancedScanner<'a> {
    text: &'a str,
    stack: Vec<u8>,
    outer_start: Option<usize>,
    in_string: bool,
    escaped: bool,
    retained: VecDeque<BalancedJsonCandidate<'a>>,
    retained_bytes: usize,
    #[cfg(test)]
    stats: BalancedJsonScanStats,
}

impl<'a> BalancedScanner<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            stack: Vec::new(),
            outer_start: None,
            in_string: false,
            escaped: false,
            retained: VecDeque::new(),
            retained_bytes: 0,
            #[cfg(test)]
            stats: BalancedJsonScanStats::default(),
        }
    }

    fn scan(&mut self) {
        for (index, byte) in self.text.bytes().enumerate() {
            #[cfg(test)]
            {
                self.stats.inspected_bytes += 1;
            }
            if self.stack.is_empty() {
                self.start_outer_if_needed(index, byte);
            } else if self.in_string {
                self.consume_string_byte(byte);
            } else {
                self.consume_structural_byte(index, byte);
            }
        }
    }

    fn start_outer_if_needed(&mut self, index: usize, byte: u8) {
        if !is_open(byte) {
            return;
        }
        self.outer_start = Some(index);
        self.stack.push(byte);
        self.record_stack_depth();
    }

    fn consume_string_byte(&mut self, byte: u8) {
        if self.escaped {
            self.escaped = false;
        } else if byte == b'\\' {
            self.escaped = true;
        } else if byte == b'"' {
            self.in_string = false;
        }
    }

    fn consume_structural_byte(&mut self, index: usize, byte: u8) {
        if byte == b'"' {
            self.in_string = true;
        } else if is_open(byte) {
            self.stack.push(byte);
            self.record_stack_depth();
        } else if is_close(byte) {
            self.close_delimiter(index, byte);
        }
    }

    fn close_delimiter(&mut self, index: usize, close: u8) {
        if !self
            .stack
            .last()
            .is_some_and(|open| delimiters_match(*open, close))
        {
            self.abandon_outer();
            return;
        }
        self.stack.pop();
        if self.stack.is_empty() {
            self.complete_outer(index + 1);
        }
    }

    fn complete_outer(&mut self, end: usize) {
        let Some(start) = self.outer_start.take() else {
            return;
        };
        #[cfg(test)]
        {
            self.stats.completed_outer_spans += 1;
        }
        self.retain(start, end);
        self.in_string = false;
        self.escaped = false;
    }

    fn abandon_outer(&mut self) {
        self.stack.clear();
        self.outer_start = None;
        self.in_string = false;
        self.escaped = false;
    }

    fn retain(&mut self, start: usize, end: usize) {
        let slice = &self.text[start..end];
        if slice.len() > MAX_BALANCED_CANDIDATE_BYTES {
            return;
        }
        self.retained_bytes += slice.len();
        self.retained.push_back(BalancedJsonCandidate {
            strategy: strategy_for(slice.as_bytes()[0]),
            slice,
        });
        self.enforce_retention_limits();
    }

    fn enforce_retention_limits(&mut self) {
        while self.retained.len() > MAX_BALANCED_CANDIDATES
            || self.retained_bytes > MAX_BALANCED_CANDIDATE_BYTES
        {
            let Some(removed) = self.retained.pop_front() else {
                break;
            };
            self.retained_bytes -= removed.slice.len();
        }
    }

    fn record_stack_depth(&mut self) {
        #[cfg(test)]
        {
            self.stats.max_stack_depth = self.stats.max_stack_depth.max(self.stack.len());
        }
    }

    fn finish(self) -> BalancedJsonScan<'a> {
        #[cfg(test)]
        let stats = BalancedJsonScanStats {
            retained_spans: self.retained.len(),
            retained_bytes: self.retained_bytes,
            ..self.stats
        };
        BalancedJsonScan {
            candidates: self.retained.into_iter().rev().collect(),
            #[cfg(test)]
            stats,
        }
    }
}

fn is_open(byte: u8) -> bool {
    matches!(byte, b'{' | b'[')
}

fn is_close(byte: u8) -> bool {
    matches!(byte, b'}' | b']')
}

fn delimiters_match(open: u8, close: u8) -> bool {
    matches!((open, close), (b'{', b'}') | (b'[', b']'))
}

fn strategy_for(open: u8) -> JsonExtractionStrategy {
    match open {
        b'{' => JsonExtractionStrategy::BalancedObject,
        b'[' => JsonExtractionStrategy::BalancedArray,
        _ => unreachable!("candidate starts with a JSON delimiter"),
    }
}
