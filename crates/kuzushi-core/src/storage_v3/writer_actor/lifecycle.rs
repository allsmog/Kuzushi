use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterActorState {
    Recovering,
    Replaying,
    Live,
    Rebuilding,
    Compacting,
    Draining,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterLifecycle {
    state: WriterActorState,
    log_head: u64,
    applied_seq: u64,
}

impl WriterLifecycle {
    pub fn recovering() -> Self {
        Self {
            state: WriterActorState::Recovering,
            log_head: 0,
            applied_seq: 0,
        }
    }

    pub fn state(self) -> WriterActorState {
        self.state
    }

    pub fn log_head(self) -> u64 {
        self.log_head
    }

    pub fn applied_seq(self) -> u64 {
        self.applied_seq
    }

    pub fn recover(&mut self, log_head: u64, applied_seq: u64) -> Result<()> {
        require_state(self.state, WriterActorState::Recovering)?;
        if applied_seq > log_head {
            bail!("projection watermark {applied_seq} is ahead of event log head {log_head}");
        }
        self.log_head = log_head;
        self.applied_seq = applied_seq;
        self.state = recovered_state(log_head, applied_seq);
        Ok(())
    }

    pub fn append_committed_event(&mut self, seq: u64) -> Result<()> {
        require_state(self.state, WriterActorState::Live)?;
        if seq <= self.log_head {
            bail!("event seq {seq} does not advance log head {}", self.log_head);
        }
        self.log_head = seq;
        Ok(())
    }

    pub fn projection_advanced(&mut self, applied_seq: u64) -> Result<()> {
        require_projection_advance_state(self.state)?;
        require_projection_watermark(applied_seq, self.log_head, self.applied_seq)?;
        self.applied_seq = applied_seq;
        self.finish_replay_if_projection_caught_up();
        Ok(())
    }

    fn finish_replay_if_projection_caught_up(&mut self) {
        if self.state == WriterActorState::Replaying && self.applied_seq == self.log_head {
            self.state = WriterActorState::Live;
        }
    }

    pub fn begin_rebuild(&mut self) -> Result<()> {
        require_state(self.state, WriterActorState::Live)?;
        self.state = WriterActorState::Rebuilding;
        self.applied_seq = 0;
        Ok(())
    }

    pub fn finish_rebuild(&mut self, applied_seq: u64) -> Result<()> {
        require_state(self.state, WriterActorState::Rebuilding)?;
        if applied_seq > self.log_head {
            bail!("rebuilt projection watermark {applied_seq} is ahead of event log head {}", self.log_head);
        }
        self.applied_seq = applied_seq;
        self.state = recovered_state(self.log_head, applied_seq);
        Ok(())
    }

    pub fn begin_compaction(&mut self) -> Result<()> {
        require_state(self.state, WriterActorState::Live)?;
        self.state = WriterActorState::Compacting;
        Ok(())
    }

    pub fn finish_compaction(&mut self, log_head: u64, applied_seq: u64) -> Result<()> {
        require_state(self.state, WriterActorState::Compacting)?;
        if applied_seq > log_head {
            bail!("compacted projection watermark {applied_seq} is ahead of event log head {log_head}");
        }
        self.log_head = log_head;
        self.applied_seq = applied_seq;
        self.state = recovered_state(log_head, applied_seq);
        Ok(())
    }

    pub fn begin_shutdown(&mut self) -> Result<()> {
        match self.state {
            WriterActorState::Live | WriterActorState::Replaying => {
                self.state = WriterActorState::Draining;
                Ok(())
            }
            _ => bail!("cannot shutdown cleanly while writer is {:?}", self.state),
        }
    }

    pub fn finish_shutdown(&mut self) -> Result<()> {
        require_state(self.state, WriterActorState::Draining)?;
        self.state = WriterActorState::Stopped;
        Ok(())
    }
}

pub(super) fn require_state(found: WriterActorState, expected: WriterActorState) -> Result<()> {
    if found != expected {
        bail!("writer state is {found:?}, expected {expected:?}");
    }
    Ok(())
}

fn recovered_state(log_head: u64, applied_seq: u64) -> WriterActorState {
    if applied_seq < log_head {
        WriterActorState::Replaying
    } else {
        WriterActorState::Live
    }
}

fn require_projection_advance_state(state: WriterActorState) -> Result<()> {
    match state {
        WriterActorState::Replaying | WriterActorState::Live => Ok(()),
        _ => bail!("cannot advance projection while writer is {state:?}"),
    }
}

fn require_projection_watermark(
    applied_seq: u64,
    log_head: u64,
    current_applied_seq: u64,
) -> Result<()> {
    if applied_seq > log_head {
        bail!("projection watermark {applied_seq} is ahead of event log head {log_head}");
    }
    if applied_seq < current_applied_seq {
        bail!("projection watermark moved backwards from {current_applied_seq} to {applied_seq}");
    }
    Ok(())
}
