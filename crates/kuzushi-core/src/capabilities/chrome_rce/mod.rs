mod adapters;
mod application;
mod domain;

pub(crate) use application::{run_review_trigger, run_scan, ChromeRcePersistence};

#[cfg(test)]
pub(crate) use domain::hot_path_finding;

#[cfg(test)]
mod tests;
