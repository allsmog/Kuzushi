use super::super::KwpError;
#[cfg(test)]
use super::injected_failure;

#[derive(Default)]
pub(super) struct FaultInjector {
    #[cfg(test)]
    pub(super) next: Option<TestAuditFault>,
}

impl FaultInjector {
    pub(super) fn fail_after_pending(&mut self) -> Result<(), KwpError> {
        self.fail_if(TestFaultStage::Pending, "pending-journal")
    }

    pub(super) fn fail_after_record(&mut self) -> Result<(), KwpError> {
        self.fail_if(TestFaultStage::Record, "record-sync")
    }

    pub(super) fn fail_after_anchor(&mut self) -> Result<(), KwpError> {
        self.fail_if(TestFaultStage::Anchor, "anchor-sync")
    }

    pub(super) fn fail_after_replacement(&mut self) -> Result<(), KwpError> {
        self.fail_if(TestFaultStage::Replacement, "replacement-journal")
    }

    pub(super) fn fail_after_recovery_anchor(&mut self) -> Result<(), KwpError> {
        self.fail_if(TestFaultStage::RecoveryAnchor, "recovery-anchor")
    }

    pub(super) fn take_recovery_marker_write(&mut self) -> bool {
        #[cfg(test)]
        if self.next == Some(TestAuditFault::RecoveryMarkerWrite) {
            self.next = None;
            return true;
        }
        false
    }

    fn fail_if(&mut self, _stage: TestFaultStage, _label: &str) -> Result<(), KwpError> {
        #[cfg(test)]
        if self.next == Some(_stage.as_fault()) {
            self.next = None;
            return Err(injected_failure(_label));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum TestFaultStage {
    Pending,
    Replacement,
    Record,
    Anchor,
    RecoveryAnchor,
}

#[cfg(test)]
impl TestFaultStage {
    fn as_fault(self) -> TestAuditFault {
        match self {
            Self::Pending => TestAuditFault::AfterPending,
            Self::Replacement => TestAuditFault::AfterReplacement,
            Self::Record => TestAuditFault::AfterRecord,
            Self::Anchor => TestAuditFault::AfterAnchor,
            Self::RecoveryAnchor => TestAuditFault::AfterRecoveryAnchor,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TestAuditFault {
    AfterPending,
    AfterReplacement,
    AfterRecord,
    AfterAnchor,
    AfterRecoveryAnchor,
    RecoveryMarkerWrite,
}
