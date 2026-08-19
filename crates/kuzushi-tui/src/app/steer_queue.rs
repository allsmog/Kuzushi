use std::collections::VecDeque;

/// One operator-submitted command waiting for the live run to finish. We store
/// the exact submitted line and re-parse it at drain time so a queued command
/// never captures a stale option snapshot (AGENTS.md: honest state over silent
/// staleness).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueuedCommand {
    /// The exact submitted line, re-parsed when the queue drains.
    pub(crate) raw: String,
    /// A short human label for the registry / activity display, e.g.
    /// `run taint-iris:hunt`.
    pub(crate) summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedEntry {
    id: u64,
    command: QueuedCommand,
}

/// The operator steer queue: the third and lowest-precedence "next tool"
/// mechanism, after the prereq chain and the planning queue. Items only
/// dispatch when no work is running, and only after chain + plan advance have
/// had their turn, so a queued steer item can never pre-empt an in-flight
/// chain or plan.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SteerQueue {
    items: VecDeque<QueuedEntry>,
    next_id: u64,
}

impl SteerQueue {
    pub(crate) fn enqueue(&mut self, cmd: QueuedCommand) {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.items.push_back(QueuedEntry {
            id: self.next_id,
            command: cmd,
        });
    }

    pub(crate) fn pop_front(&mut self) -> Option<QueuedCommand> {
        self.items.pop_front().map(|entry| entry.command)
    }

    #[cfg(test)]
    pub(crate) fn peek(&self) -> Option<&QueuedCommand> {
        self.items.front().map(|entry| &entry.command)
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (String, &QueuedCommand)> {
        self.items
            .iter()
            .map(|entry| (Self::selector(entry.id), &entry.command))
    }

    /// The stable selector a queued row renders under in the registry. The
    /// sequence is assigned at enqueue time and never changes while queued.
    fn selector(id: u64) -> String {
        format!("queued-{id}")
    }

    /// Drop every pending item (operator full-stop, e.g. Ctrl+C abort).
    /// Returns the drained commands so the caller can report exactly what was
    /// dropped instead of silently discarding queued work (AGENTS.md: honest
    /// state).
    pub(crate) fn drain_all(&mut self) -> Vec<QueuedCommand> {
        self.items.drain(..).map(|entry| entry.command).collect()
    }

    /// Remove a queued item named by its stable `queued-<n>` selector.
    /// Returns the removed command so the caller can report what it dropped.
    pub(crate) fn remove_matching(&mut self, token: &str) -> Option<QueuedCommand> {
        let id = token.strip_prefix("queued-")?.parse::<u64>().ok()?;
        let index = self.items.iter().position(|entry| entry.id == id)?;
        self.items.remove(index).map(|entry| entry.command)
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
    fn remove_matching_targets_stable_id() {
        let mut queue = SteerQueue::default();
        queue.enqueue(cmd("run a"));
        queue.enqueue(cmd("run b"));
        let removed = queue.remove_matching("queued-1").unwrap();
        assert_eq!(removed.raw, "run a");
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.peek().unwrap().raw, "run b");
        assert_eq!(queue.iter().next().unwrap().0, "queued-2");
    }

    #[test]
    fn selectors_do_not_renumber_after_remove_or_drain() {
        let mut queue = SteerQueue::default();
        queue.enqueue(cmd("run a"));
        queue.enqueue(cmd("run b"));
        queue.enqueue(cmd("run c"));

        assert_eq!(queue.remove_matching("queued-1").unwrap().raw, "run a");
        assert_eq!(queue.pop_front().unwrap().raw, "run b");
        queue.enqueue(cmd("run d"));

        let selectors = queue.iter().map(|(id, _)| id).collect::<Vec<_>>();
        assert_eq!(selectors, ["queued-3", "queued-4"]);
        assert_eq!(queue.remove_matching("queued-2"), None);
        assert_eq!(queue.remove_matching("queued-3").unwrap().raw, "run c");
    }

    #[test]
    fn drain_all_empties_the_queue_and_returns_the_dropped_items() {
        let mut queue = SteerQueue::default();
        queue.enqueue(cmd("run a"));
        queue.enqueue(cmd("run b"));
        let dropped = queue.drain_all();
        assert_eq!(dropped.len(), 2);
        assert_eq!(dropped[0].raw, "run a");
        assert_eq!(dropped[1].raw, "run b");
        assert!(queue.is_empty());
        assert!(queue.drain_all().is_empty());
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
