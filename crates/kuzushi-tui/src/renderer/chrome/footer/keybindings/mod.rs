use super::*;

mod active_and_idle;
mod catalog_and_finding;
mod defaults;
mod system;
mod workflow;
mod workspace;

pub(in crate::renderer::chrome::footer::keybindings) use catalog_and_finding::*;
pub(in crate::renderer::chrome::footer::keybindings) use defaults::*;
pub(in crate::renderer::chrome::footer::keybindings) use system::*;
pub(in crate::renderer::chrome::footer::keybindings) use workflow::*;
pub(in crate::renderer::chrome::footer::keybindings) use workspace::*;

pub(crate) use active_and_idle::keybindings;
