//! M2 §2.3 — bug-bounty HTTP evidence importers.
//!
//! These adapters parse Burp Suite XML and HAR captures into the
//! canonical `Finding` shape with `http-request` evidence. They live
//! under `findings::import` because the output is a Finding, not a
//! recon artefact — HTTP evidence belongs in the findings ledger so
//! triage/verify/patch workflows can reference it.

mod burp_xml;
mod har;

pub use burp_xml::import_burp_xml;
pub use har::import_har;
