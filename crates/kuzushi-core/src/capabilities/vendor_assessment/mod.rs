mod adapters;
mod application;
mod domain;

pub(crate) use application::{assess, attach, prompts, scope};
pub(crate) use domain::{AttachmentInput, ScopeUpdate};

#[cfg(test)]
mod tests;
