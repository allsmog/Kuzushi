use super::{PendingItem, WRITER_CAPACITY};
use crate::run_lifecycle::{
    record_coalesced_progress, record_writer_saturation, DiagnosticLevel, RunItemId,
    RunItemRecord, RunItemSource, RunItemV1, SafeText, RUN_PROGRESS_SATURATION_MARKER,
};
use anyhow::Result;
use std::collections::BTreeMap;

pub(super) struct CoalescedItems {
    items: BTreeMap<RunItemId, (RunItemRecord, u64)>,
    saturated_progress_item_id: Option<RunItemId>,
    saturated_omitted: u64,
}

impl Default for CoalescedItems {
    fn default() -> Self {
        Self {
            items: BTreeMap::new(),
            saturated_progress_item_id: None,
            saturated_omitted: 0,
        }
    }
}

impl CoalescedItems {
    pub(super) fn insert(&mut self, record: RunItemRecord) -> Result<()> {
        if let Some((current, omitted)) = self.items.get_mut(&record.item_id) {
            *current = record;
            *omitted = omitted.saturating_add(1);
            return Ok(());
        }
        if self.items.len() >= WRITER_CAPACITY {
            record_writer_saturation();
            self.saturated_progress_item_id
                .get_or_insert(record.item_id);
            self.saturated_omitted = self.saturated_omitted.saturating_add(1);
            return Ok(());
        }
        self.items.insert(record.item_id, (record, 0));
        Ok(())
    }

    pub(super) fn drain(&mut self) -> Vec<PendingItem> {
        let saturated = self.saturated_progress_item_id.take().map(|item_id| {
            saturation_records(item_id, std::mem::take(&mut self.saturated_omitted))
        });
        let mut pending = std::mem::take(&mut self.items)
            .into_iter()
            .flat_map(|(item_id, (record, omitted))| pending_records(item_id, record, omitted))
            .collect::<Vec<_>>();
        if let Some(saturated) = saturated {
            pending.splice(0..0, saturated);
        }
        pending
    }
}

fn saturation_records(progress_item_id: RunItemId, omitted_count: u64) -> Vec<PendingItem> {
    record_coalesced_progress(omitted_count);
    vec![
        truncation_record(progress_item_id, omitted_count),
        PendingItem {
            record: RunItemRecord::new(
                RunItemId::new(),
                RunItemSource::Persistence,
                RunItemV1::DiagnosticNotice {
                    level: DiagnosticLevel::Warning,
                    message: SafeText::operator_visible(RUN_PROGRESS_SATURATION_MARKER),
                },
            ),
            reply: None,
        },
    ]
}

fn pending_records(
    progress_item_id: RunItemId,
    record: RunItemRecord,
    omitted: u64,
) -> Vec<PendingItem> {
    let mut pending = Vec::with_capacity(usize::from(omitted > 0) + 1);
    if omitted > 0 {
        record_coalesced_progress(omitted);
        pending.push(truncation_record(progress_item_id, omitted));
    }
    pending.push(PendingItem {
        record,
        reply: None,
    });
    pending
}

fn truncation_record(progress_item_id: RunItemId, omitted_count: u64) -> PendingItem {
    let item = RunItemV1::ProgressTruncated {
        progress_item_id,
        omitted_count,
    };
    PendingItem {
        record: RunItemRecord::new(RunItemId::new(), RunItemSource::Persistence, item),
        reply: None,
    }
}
