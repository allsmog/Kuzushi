pub(in crate::renderer) use super::prelude::*;
pub(in crate::renderer) use super::*;

mod siblings;
pub(crate) use siblings::*;
mod items_2;
/// Tally `+` / `-` line counts and `+++` file headers in a unified diff.

/// Render a unified diff into styled `Line`s matching
/// `design/mockups/patch.jsx::diff`:
///   `+ added line`  in c-success
///   `- deleted line` in c-danger
///   `  ctx line`    in c-muted
///   `@@ hunk @@`    in c-subtle
///   `--- a/path`    file header in c-accent
mod patch_lines;
pub(crate) use patch_lines::patch_lines;
