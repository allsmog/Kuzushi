use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

const MAX_FAILURE_STAGE_CHARS: usize = 160;
const MAX_MODEL_CALL_ID_CHARS: usize = 64;
const ADAPTIVE_THINKING_DETAIL: &str =
    "temperature is incompatible with adaptive thinking; omit the pinned temperature";
const OPENAI_OAUTH_DETAIL: &str =
    "OpenAI OAuth authentication failed; run `kuzushi auth login openai`.";
const MODEL_UNAVAILABLE_DETAIL: &str = "The selected model is unavailable for this provider or account. Choose an available model explicitly.";
const ALLOWANCE_UNSUPPORTED_DETAIL: &str = "The selected runtime bridge does not enforce provider-call allowances. Select a compatible adapter explicitly.";
const ALLOWANCE_HANDSHAKE_DETAIL: &str = "The runtime bridge did not acknowledge provider-call allowances before its startup deadline. No provider request was admitted.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
/// Provider-neutral categories safe to expose in lifecycle artifacts and UI.
pub enum RuntimeFailureClass {
    Authentication,
    BridgeInternal,
    Cancelled,
    McpTimeout,
    McpUnavailable,
    ProviderRejected,
    ProviderResponseInvalid,
    ProviderUnavailable,
    RateLimited,
    SdkClientValidation,
    Timeout,
    Transport,
    RuntimeError,
    AllowanceRefused,
}

impl RuntimeFailureClass {
    pub fn as_str(self) -> &'static str {
        FAILURE_CLASS_NAMES[self as usize]
    }

    pub fn public_message(self) -> &'static str {
        PUBLIC_FAILURE_MESSAGES[self as usize]
    }

    pub fn from_safe_class(value: &str) -> Self {
        FAILURE_CLASS_NAMES
            .iter()
            .position(|candidate| *candidate == value)
            .map(runtime_failure_class_at)
            .unwrap_or(Self::RuntimeError)
    }
}

const FAILURE_CLASS_NAMES: [&str; 14] = [
    "authentication",
    "bridge_internal",
    "cancelled",
    "mcp_timeout",
    "mcp_unavailable",
    "provider_rejected",
    "provider_response_invalid",
    "provider_unavailable",
    "rate_limited",
    "sdk_client_validation",
    "timeout",
    "transport",
    "runtime_error",
    "allowance_refused",
];

const PUBLIC_FAILURE_MESSAGES: [&str; 14] = [
    "Provider authentication failed",
    "Bridge operation failed",
    "Model operation was cancelled",
    "MCP tool request timed out",
    "Restore the missing code-analysis component: from source run `cargo build --workspace`; otherwise reinstall Kuzushi",
    "Provider rejected the request",
    "Provider returned an invalid response",
    "Provider is temporarily unavailable",
    "Provider rate limited the request",
    "Provider SDK rejected incompatible client-side invocation parameters before sending",
    "Provider request timed out",
    "Provider request failed before a response was received",
    "Model runtime failed",
    "Investigation allowance refused this request; finish and report or review the remaining work",
];

fn runtime_failure_class_at(index: usize) -> RuntimeFailureClass {
    use RuntimeFailureClass::*;
    const CLASSES: [RuntimeFailureClass; 14] = [
        Authentication,
        BridgeInternal,
        Cancelled,
        McpTimeout,
        McpUnavailable,
        ProviderRejected,
        ProviderResponseInvalid,
        ProviderUnavailable,
        RateLimited,
        SdkClientValidation,
        Timeout,
        Transport,
        RuntimeError,
        AllowanceRefused,
    ];
    CLASSES[index]
}

impl fmt::Display for RuntimeFailureClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
/// Bounded, redacted metadata for one failed model-runtime operation.
pub struct RuntimeFailureMetadata {
    /// Stable provider-neutral failure category.
    pub error_class: RuntimeFailureClass,
    /// Valid HTTP response status when the provider returned one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Canonical allowlisted diagnostic detail. Raw provider text is never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Durable lifecycle identity for the failed model call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_call_id: Option<String>,
    /// Logical execution stage that owned the model call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
}

impl RuntimeFailureMetadata {
    pub fn new(
        error_class: RuntimeFailureClass,
        http_status: Option<u16>,
        detail: Option<&str>,
    ) -> Self {
        Self {
            error_class,
            http_status: valid_http_status(http_status),
            detail: allowlisted_failure_detail(error_class, detail),
            model_call_id: None,
            stage: None,
        }
    }

    pub fn with_model_call(mut self, call_id: impl fmt::Display, stage: Option<&str>) -> Self {
        self.model_call_id =
            safe_optional_text(Some(&call_id.to_string()), MAX_MODEL_CALL_ID_CHARS);
        self.stage = safe_optional_text(stage, MAX_FAILURE_STAGE_CHARS);
        self
    }

    pub fn public_message(&self) -> String {
        match self.http_status {
            Some(status) => format!("{} (HTTP {status}).", self.error_class.public_message()),
            None => format!("{}.", self.error_class.public_message()),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeFailureMetadataWire {
    error_class: RuntimeFailureClass,
    #[serde(default)]
    http_status: Option<u16>,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    model_call_id: Option<String>,
    #[serde(default)]
    stage: Option<String>,
}

impl<'de> Deserialize<'de> for RuntimeFailureMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RuntimeFailureMetadataWire::deserialize(deserializer)?;
        let mut safe = Self::new(wire.error_class, wire.http_status, wire.detail.as_deref());
        safe = safe.with_model_call(
            wire.model_call_id.as_deref().unwrap_or_default(),
            wire.stage.as_deref(),
        );
        if safe.model_call_id.as_deref() == Some("") {
            safe.model_call_id = None;
        }
        let persisted = (wire.detail, wire.model_call_id, wire.stage);
        let normalized = (
            safe.detail.clone(),
            safe.model_call_id.clone(),
            safe.stage.clone(),
        );
        if persisted != normalized || wire.http_status != safe.http_status {
            return Err(serde::de::Error::custom(
                "runtime failure metadata violates safety policy",
            ));
        }
        Ok(safe)
    }
}

#[derive(Debug, Clone)]
/// Error wrapper that transports typed failure metadata through `anyhow`.
pub struct RuntimeFailure {
    metadata: RuntimeFailureMetadata,
}

impl RuntimeFailure {
    pub fn allowance_handshake_timeout() -> Self {
        Self::new(RuntimeFailureMetadata::new(
            RuntimeFailureClass::AllowanceRefused,
            None,
            Some(ALLOWANCE_HANDSHAKE_DETAIL),
        ))
    }

    pub fn allowance_unsupported() -> Self {
        Self::new(RuntimeFailureMetadata::new(
            RuntimeFailureClass::AllowanceRefused,
            None,
            Some(ALLOWANCE_UNSUPPORTED_DETAIL),
        ))
    }
    pub fn new(metadata: RuntimeFailureMetadata) -> Self {
        Self { metadata }
    }

    pub fn metadata(&self) -> &RuntimeFailureMetadata {
        &self.metadata
    }
}

impl fmt::Display for RuntimeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.metadata.public_message())
    }
}

impl std::error::Error for RuntimeFailure {}

pub fn runtime_failure_metadata(error: &anyhow::Error) -> Option<RuntimeFailureMetadata> {
    error
        .chain()
        .find_map(|source| source.downcast_ref::<RuntimeFailure>())
        .map(|failure| failure.metadata().clone())
}

fn valid_http_status(status: Option<u16>) -> Option<u16> {
    status.filter(|status| (100..=599).contains(status))
}

fn safe_optional_text(value: Option<&str>, limit: usize) -> Option<String> {
    let value = value.map(str::trim).filter(|value| !value.is_empty())?;
    let redacted = crate::session_transcript::redaction::redact_text(value);
    Some(redacted.chars().take(limit).collect())
}

fn allowlisted_failure_detail(
    error_class: RuntimeFailureClass,
    detail: Option<&str>,
) -> Option<String> {
    let detail = detail?.to_ascii_lowercase();
    SAFE_DETAILS
        .iter()
        .find(|(class, required, _)| {
            *class == error_class && required.iter().all(|text| detail.contains(text))
        })
        .map(|(_, _, canonical)| canonical.to_string())
}

const SAFE_DETAILS: &[(RuntimeFailureClass, &[&str], &str)] = &[
    (
        RuntimeFailureClass::AllowanceRefused,
        &["the runtime bridge did not acknowledge provider-call allowances before its startup deadline. no provider request was admitted."],
        ALLOWANCE_HANDSHAKE_DETAIL,
    ),
    (
        RuntimeFailureClass::AllowanceRefused,
        &["the selected runtime bridge does not enforce provider-call allowances. select a compatible adapter explicitly."],
        ALLOWANCE_UNSUPPORTED_DETAIL,
    ),
    (
        RuntimeFailureClass::SdkClientValidation,
        &["temperature", "thinking"],
        ADAPTIVE_THINKING_DETAIL,
    ),
    (
        RuntimeFailureClass::Authentication,
        &["openai oauth authentication failed"],
        OPENAI_OAUTH_DETAIL,
    ),
    (
        RuntimeFailureClass::ProviderRejected,
        &["the selected model is unavailable for this provider or account. choose an available model explicitly."],
        MODEL_UNAVAILABLE_DETAIL,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowance_failure_roundtrips_as_a_safe_distinct_class() {
        let failure = RuntimeFailure::allowance_unsupported();
        let metadata = failure.metadata();
        assert_eq!(RuntimeFailureClass::from_safe_class("allowance_refused"), metadata.error_class);
        assert_eq!(metadata.error_class.to_string(), "allowance_refused");
        let value = serde_json::to_value(metadata).unwrap();
        assert_eq!(value["errorClass"], "allowance_refused");
        assert_eq!(serde_json::from_value::<RuntimeFailureMetadata>(value).unwrap(), *metadata);
        let unknown = RuntimeFailureMetadata::new(RuntimeFailureClass::AllowanceRefused, None, Some("private ledger detail"));
        assert_eq!(unknown.detail, None);
    }

    #[test]
    fn metadata_keeps_only_allowlisted_canonical_detail() {
        let metadata = RuntimeFailureMetadata::new(
            RuntimeFailureClass::SdkClientValidation,
            None,
            Some("temperature incompatible with adaptive thinking; source=private"),
        );

        let serialized = serde_json::to_string(&metadata).unwrap();
        assert_eq!(metadata.detail.as_deref(), Some(ADAPTIVE_THINKING_DETAIL));
        assert!(!serialized.contains("private"));

        let arbitrary = RuntimeFailureMetadata::new(
            RuntimeFailureClass::ProviderRejected,
            Some(400),
            Some("proprietary source excerpt without a secret pattern"),
        );
        assert_eq!(arbitrary.detail, None);
    }

    #[test]
    fn unsafe_persisted_metadata_is_rejected() {
        let value = serde_json::json!({
            "errorClass": "runtime_error",
            "detail": "token=secret-value"
        });
        assert!(serde_json::from_value::<RuntimeFailureMetadata>(value).is_err());
    }

    #[test]
    fn unavailable_model_detail_roundtrips_without_accepting_raw_provider_content() {
        let metadata = RuntimeFailureMetadata::new(
            RuntimeFailureClass::ProviderRejected,
            Some(400),
            Some(MODEL_UNAVAILABLE_DETAIL),
        );
        let value = serde_json::to_value(&metadata).unwrap();
        assert_eq!(value["detail"], MODEL_UNAVAILABLE_DETAIL);
        assert_eq!(
            serde_json::from_value::<RuntimeFailureMetadata>(value.clone()).unwrap(),
            metadata
        );
        let mut unsafe_value = value;
        unsafe_value["detail"] = format!("{MODEL_UNAVAILABLE_DETAIL} PRIVATE_SOURCE").into();
        assert!(serde_json::from_value::<RuntimeFailureMetadata>(unsafe_value).is_err());
        let wrong_class = RuntimeFailureMetadata::new(
            RuntimeFailureClass::Authentication,
            Some(401),
            Some(MODEL_UNAVAILABLE_DETAIL),
        );
        assert_eq!(wrong_class.detail, None);
    }
}
