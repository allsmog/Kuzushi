mod async_and_rpc;
mod data_and_io;
mod trust_and_identity;

use super::super::*;

pub(super) struct JvmLineDetector {
    kind: AttackSurfaceKind,
    title: &'static str,
    boundary: &'static str,
    detector: &'static str,
    needles: &'static [&'static str],
}

impl JvmLineDetector {
    pub(super) fn matches(&self, line: &str) -> bool {
        line_contains_any(line, self.needles)
    }

    pub(super) fn surface(
        &self,
        source_file: &InventorySourceFile,
        framework: Option<&str>,
        line_number: u32,
        detail: &str,
    ) -> AttackSurfaceDraft {
        surface(
            self.kind,
            source_file,
            framework,
            line_number,
            self.title,
            detail,
            None,
            None,
            Some(self.boundary),
            json!({ "source": "source_line", "detector": self.detector }),
        )
    }
}

pub(super) const JVM_LINE_DETECTOR_GROUPS: &[&[JvmLineDetector]] = &[
    trust_and_identity::TRUST_AND_IDENTITY_DETECTORS,
    data_and_io::PARSER_AND_UPLOAD_DETECTORS,
    data_and_io::STORE_DETECTORS,
    data_and_io::CLIENT_AND_PROCESS_DETECTORS,
    async_and_rpc::ASYNC_AND_RPC_DETECTORS,
];
