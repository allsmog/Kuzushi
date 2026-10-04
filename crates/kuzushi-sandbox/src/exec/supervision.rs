use kuzushi_mcp_common::process::ParentDeathProcessGroup;
use std::io;
use tokio::process::{Child, Command};

/// An unreaped Unix guard owns the group identity; Windows uses a kill-on-close
/// Job Object. Repeated cleanup cannot signal a recycled child process ID.
pub(super) struct ProcessGroup(ParentDeathProcessGroup);

impl ProcessGroup {
    pub(super) fn configure(command: &mut Command) -> io::Result<Self> {
        ParentDeathProcessGroup::configure(command)
            .map(Self)
            .map_err(io::Error::other)
    }

    pub(super) fn attach(&mut self, child: &Child) -> io::Result<()> {
        self.0.attach_child(child).map_err(io::Error::other)
    }

    pub(super) fn terminate(&self) {
        self.0.kill();
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.terminate();
    }
}
