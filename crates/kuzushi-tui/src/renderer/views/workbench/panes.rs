//! Pure pane-body line builders for the Workbench command center. Shared by the
//! frame renderer (each list drawn inside a bordered `Block`) and the plain
//! `workbench_lines` path (each list stacked under a text divider).

use super::*;

mod review_queue;
pub(super) use review_queue::review_queue_pane_lines;
