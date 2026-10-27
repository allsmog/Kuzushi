use super::*;

impl ShellApp {
    pub(super) fn spawn_relationship_bulk_write(&mut self, review: RelationshipBulkReview) {
        if self.runtime_state.relationship_write.is_some() {
            return;
        }
        let config = self.config().clone();
        let origin_scroll = review.origin_scroll;
        let target = review.target.clone();
        let worker_target = target.clone();
        let request = kuzushi_core::workspace::FindingRelationshipBatchReviewRequest {
            relationships: review.records.clone(),
            state: review.state,
            note: review.field.text().into(),
        };
        let handle = std::thread::spawn(move || {
            let workspace =
                kuzushi_core::WorkspaceTarget::new(worker_target).map_err(|e| e.to_string())?;
            kuzushi_core::workspace::record_finding_relationship_batch_review(
                &workspace, &config, &request,
            )
            .map_err(|e| format!("{e:#}"))
        });
        self.runtime_state.relationship_write = Some(RelationshipWrite {
            target,
            draft: RelationshipWriteDraft::Batch(review),
            handle,
        });
        self.router.relationships.bulk = None;
        self.router.default_scroll_mut().set(origin_scroll);
        self.router.relationships.notice = Some(
            "Saving the reviewed selection atomically; finding verdicts stay separate.".into(),
        );
    }

    pub(super) fn spawn_relationship_write(&mut self, note: RelationshipNote) {
        if self.runtime_state.relationship_write.is_some() {
            return;
        }
        let config = self.config().clone();
        let target = note.target.clone();
        let request = FindingRelationshipReviewRequest {
            id: note.relationship.id.clone(),
            state: note.state,
            note: note.field.text().into(),
            expected_revision: note.relationship.revision,
        };
        let worker_target = target.clone();
        let handle = std::thread::spawn(move || {
            let workspace =
                kuzushi_core::WorkspaceTarget::new(worker_target).map_err(|e| e.to_string())?;
            kuzushi_core::workspace::record_finding_relationship_review(
                &workspace, &config, &request,
            )
            .map(|record| vec![record])
            .map_err(|e| format!("{e:#}"))
        });
        self.runtime_state.relationship_write = Some(RelationshipWrite {
            target,
            draft: note.into(),
            handle,
        });
        self.router.relationships.note = None;
        self.router.relationships.notice =
            Some("Saving relationship decision; finding verdicts stay separate.".into());
    }

    pub(crate) fn poll_relationship_write(&mut self) -> bool {
        let Some(pending) = self.runtime_state.relationship_write.as_ref() else {
            return false;
        };
        if !pending.handle.is_finished() {
            return false;
        }
        let pending = self.runtime_state.relationship_write.take().unwrap();
        let result = pending
            .handle
            .join()
            .unwrap_or_else(|_| Err("Relationship writer stopped unexpectedly".into()));
        self.finish_relationship_write(pending.target, pending.draft, result);
        true
    }

    pub(super) fn finish_relationship_write(
        &mut self,
        target: PathBuf,
        draft: impl Into<RelationshipWriteDraft>,
        result: Result<Vec<FindingRelationship>, String>,
    ) {
        let draft = draft.into();
        if self.target() != Some(target.as_path()) {
            self.set_info_notice(
                "relationships",
                "Relationship write finished for the earlier target; inspect its recorded state.",
            );
            return;
        }
        let result = result.and_then(|records| confirmed_records(&draft, records));
        match result {
            Ok(records) => {
                self.acknowledge_relationship_records(&records);
                self.router.relationships.note = None;
                self.router.relationships.bulk = None;
                if matches!(draft, RelationshipWriteDraft::Batch(_)) {
                    self.router.relationships.selection.clear();
                }
                self.refresh_relationships();
                self.workbench_cache().borrow_mut().group_pages.clear();
                self.router.relationships.notice =
                    Some("Saved. Finding verdicts stay separate.".into());
            }
            Err(error) => {
                self.restore_relationship_write_draft(draft);
                self.router.relationships.notice = Some(format!(
                    "Relationship decision not confirmed: {error}. Esc goes back. In the browser, c clears a bulk selection and R refreshes. Inspect recorded state before reviewing again."
                ))
            }
        }
    }

    fn acknowledge_relationship_records(&mut self, records: &[FindingRelationship]) {
        self.pin_current_relationship();
        let Some(pinned) = &self.router.relationships.pinned else {
            return;
        };
        if let Some(record) = records.iter().find(|record| record.id == pinned.id) {
            self.pin_relationship(record.clone());
        }
    }

    fn restore_relationship_write_draft(&mut self, draft: RelationshipWriteDraft) {
        match draft {
            RelationshipWriteDraft::Single(note) => self.router.relationships.note = Some(note),
            RelationshipWriteDraft::Batch(review) => self.router.relationships.bulk = Some(review),
        }
    }
}

fn confirmed_records(
    draft: &RelationshipWriteDraft,
    records: Vec<FindingRelationship>,
) -> Result<Vec<FindingRelationship>, String> {
    let expected = expected_records(draft).map_err(|error| error.to_string())?;
    if records != expected {
        return Err("Saved relationship receipt does not match the reviewed selection".into());
    }
    Ok(records)
}

fn expected_records(draft: &RelationshipWriteDraft) -> anyhow::Result<Vec<FindingRelationship>> {
    let (records, state, note) = match draft {
        RelationshipWriteDraft::Single(note) => (
            std::slice::from_ref(&note.relationship),
            note.state,
            note.field.text(),
        ),
        RelationshipWriteDraft::Batch(review) => {
            (review.records.as_slice(), review.state, review.field.text())
        }
    };
    records
        .iter()
        .map(|record| record.review(state, note.trim().into(), record.revision))
        .collect()
}
