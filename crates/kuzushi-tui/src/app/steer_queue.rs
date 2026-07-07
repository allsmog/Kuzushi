use std::collections::VecDeque;

/// One operator-submitted command waiting for the live run to finish. We store
/// the exact submitted line and re-parse it at drain time so a queued command
/// never captures a stale option snapshot (CLAUDE.md: honest state over silent
/// staleness).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueuedCommand {
    /// The exact submitted line, re-parsed when the queue drains.
    pub(crate) raw: String,
    /// A short human label for the registry / activity display, e.g.
    /// `run taint-iris:hunt`.
    pub(crate) summary: String,
}

/// The operator steer queue: the third and lowest-precedence "next tool"
/// mechanism, after the prereq chain and the planning queue. Items only
/// dispatch when no work is running, and only after chain + plan advance have
/// had their turn, so a queued steer item can never pre-empt an in-flight
/// chain or plan.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SteerQueue {
    items: VecDeque<QueuedCommand>,
}

impl SteerQueue {
    pub(crate) fn enqueue(&mut self, cmd: QueuedCommand) {
        self.items.push_back(cmd);
    }

    pub(crate) fn pop_front(&mut self) -> Option<QueuedCommand> {
        self.items.pop_front()
    }

    pub(crate) fn peek(&self) -> Option<&QueuedCommand> {
        self.items.front()
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &QueuedCommand> {
        self.items.iter()
    }

    /// The synthetic run-id a queued row renders under in the registry:
    /// `queued-<n>` (1-based, in queue order). Used to target `jobs -k`.
    pub(crate) fn synthetic_id(index: usize) -> String {
        format!("queued-{}", index + 1)
    }

    /// Remove a queued item named by its synthetic `queued-<n>` id (1-based).
    /// Returns the removed command so the caller can report what it dropped.
    pub(crate) fn remove_matching(&mut self, token: &str) -> Option<QueuedCommand> {
        let index = token.strip_prefix("queued-")?.parse::<usize>().ok()?;
        if index == 0 {
            return None;
        }
        self.items.remove(index - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(raw: &str) -> QueuedCommand {
        QueuedCommand {
            raw: raw.to_string(),
            summary: raw.to_string(),
        }
    }

    #[test]
    fn enqueue_and_pop_are_fifo() {
        let mut queue = SteerQueue::default();
        queue.enqueue(cmd("run a"));
        queue.enqueue(cmd("run b"));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop_front().unwrap().raw, "run a");
        assert_eq!(queue.pop_front().unwrap().raw, "run b");
        assert!(queue.is_empty());
    }

    #[test]
    fn remove_matching_targets_synthetic_id() {
        let mut queue = SteerQueue::default();
        queue.enqueue(cmd("run a"));
        queue.enqueue(cmd("run b"));
        assert_eq!(SteerQueue::synthetic_id(0), "queued-1");
        let removed = queue.remove_matching("queued-1").unwrap();
        assert_eq!(removed.raw, "run a");
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.peek().unwrap().raw, "run b");
    }

    #[test]
    fn remove_matching_rejects_unknown_or_out_of_range_tokens() {
        let mut queue = SteerQueue::default();
        queue.enqueue(cmd("run a"));
        assert!(queue.remove_matching("queued-0").is_none());
        assert!(queue.remove_matching("queued-9").is_none());
        assert!(queue.remove_matching("run-123").is_none());
        assert_eq!(queue.len(), 1);
    }
}
