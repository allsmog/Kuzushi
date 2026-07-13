use super::*;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[derive(Debug, Default)]
pub(crate) struct PreparedProcessGroup {
    process_group_id: Option<u32>,
    #[cfg(unix)]
    parent_death_guard: Option<ParentDeathGuard>,
}

impl PreparedProcessGroup {
    pub(crate) fn configure(command: &mut Command) -> Result<Self> {
        #[cfg(unix)]
        {
            let guard = ParentDeathGuard::spawn()?;
            let process_group_id = guard.process_group_id();
            configure_process_group(command, process_group_id);
            return Ok(Self {
                process_group_id: Some(process_group_id),
                parent_death_guard: Some(guard),
            });
        }

        #[cfg(not(unix))]
        {
            let _ = command;
            Ok(Self::default())
        }
    }

    pub(crate) fn process_group_id(&self) -> Option<u32> {
        self.process_group_id
    }

    #[cfg(unix)]
    pub(in crate::scan) fn into_parts(mut self) -> (Option<u32>, Option<ParentDeathGuard>) {
        (self.process_group_id.take(), self.parent_death_guard.take())
    }

    #[cfg(not(unix))]
    pub(in crate::scan) fn into_process_group_id(mut self) -> Option<u32> {
        self.process_group_id.take()
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command, process_group_id: u32) {
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, process_group_id as libc::pid_t) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
