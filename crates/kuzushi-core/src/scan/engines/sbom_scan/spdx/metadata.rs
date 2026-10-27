use serde_json::{json, Value};

pub(super) struct ExportMetadata {
    pub(super) created: String,
    pub(super) namespace: String,
}

impl ExportMetadata {
    pub(super) fn now() -> Self {
        let now = time::OffsetDateTime::now_utc();
        Self {
            created: format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                now.year(),
                u8::from(now.month()),
                now.day(),
                now.hour(),
                now.minute(),
                now.second()
            ),
            namespace: format!("https://kuzushi.local/spdx/{}", uuid::Uuid::new_v4()),
        }
    }

    pub(super) fn annotation(&self, comment: String) -> Value {
        json!({
            "annotationType": "OTHER",
            "annotationDate": self.created,
            "annotator": "Tool: Kuzushi sbom-scan",
            "comment": comment,
        })
    }
}
