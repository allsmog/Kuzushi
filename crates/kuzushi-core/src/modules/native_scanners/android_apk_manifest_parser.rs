use super::*;

use quick_xml::events::Event;
use quick_xml::Reader;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub(in crate::modules) struct ParsedManifest {
    pub(in crate::modules) package: Option<String>,
    pub(in crate::modules) target_sdk: Option<u32>,
    pub(in crate::modules) application: ApplicationAttrs,
    pub(in crate::modules) components: Vec<Component>,
    pub(in crate::modules) permissions: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub(in crate::modules) struct ApplicationAttrs {
    pub(in crate::modules) debuggable: Option<bool>,
    pub(in crate::modules) allow_backup: Option<bool>,
    pub(in crate::modules) uses_cleartext_traffic: Option<bool>,
    pub(in crate::modules) network_security_config: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::modules) enum ComponentKind {
    Activity,
    ActivityAlias,
    Service,
    Receiver,
    Provider,
}

impl ComponentKind {
    pub(in crate::modules) fn label(self) -> &'static str {
        match self {
            Self::Activity => "activity",
            Self::ActivityAlias => "activity-alias",
            Self::Service => "service",
            Self::Receiver => "receiver",
            Self::Provider => "provider",
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct Component {
    pub(in crate::modules) kind: ComponentKind,
    pub(in crate::modules) name: String,
    pub(in crate::modules) exported: Option<bool>,
    pub(in crate::modules) permission: Option<String>,
    pub(in crate::modules) grant_uri_permissions: Option<bool>,
    pub(in crate::modules) intent_filters: Vec<IntentFilter>,
}

impl Component {
    pub(in crate::modules) fn is_effectively_exported(&self) -> bool {
        if let Some(value) = self.exported {
            return value;
        }
        !self.intent_filters.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub(in crate::modules) struct IntentFilter {
    pub(in crate::modules) actions: Vec<String>,
    pub(in crate::modules) categories: Vec<String>,
    pub(in crate::modules) schemes: Vec<String>,
    pub(in crate::modules) hosts: Vec<String>,
}

impl IntentFilter {
    pub(in crate::modules) fn is_browseable_deeplink(&self) -> bool {
        let browseable = self
            .categories
            .iter()
            .any(|c| c.ends_with(".BROWSABLE") || c == "android.intent.category.BROWSABLE");
        let view = self
            .actions
            .iter()
            .any(|a| a == "android.intent.action.VIEW");
        browseable && view && !self.schemes.is_empty()
    }
}

pub(in crate::modules) fn parse_manifest_file(path: &Path) -> Result<ParsedManifest> {
    let bytes = fs::read(path)
        .map_err(|error| anyhow::anyhow!("could not read {}: {error}", path.display()))?;
    parse_manifest_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid XML in {}: {error}", path.display()))
}

pub(in crate::modules) fn parse_manifest_bytes(bytes: &[u8]) -> Result<ParsedManifest> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut state = ParserState::default();
    let mut buffer = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(start) => state.on_open(&start)?,
            Event::Empty(start) => {
                state.on_open(&start)?;
                state.on_close(&start);
            }
            Event::End(end) => state.on_close_owned(&end),
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(state.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <application android:debuggable="true" android:allowBackup="true"
                 android:usesCleartextTraffic="true">
        <activity android:name=".LaunchActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="lyft" android:host="ride"/>
            </intent-filter>
        </activity>
        <receiver android:name=".SmsReceiver">
            <intent-filter>
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>"#;

    #[test]
    fn parses_application_flags() {
        let manifest = parse_manifest_bytes(SAMPLE.as_bytes()).unwrap();
        assert_eq!(manifest.package.as_deref(), Some("com.example.app"));
        assert_eq!(manifest.target_sdk, Some(33));
        assert_eq!(manifest.application.debuggable, Some(true));
        assert_eq!(manifest.application.allow_backup, Some(true));
        assert_eq!(manifest.application.uses_cleartext_traffic, Some(true));
    }

    #[test]
    fn parses_permissions() {
        let manifest = parse_manifest_bytes(SAMPLE.as_bytes()).unwrap();
        assert!(manifest
            .permissions
            .contains(&"android.permission.INTERNET".to_string()));
    }

    #[test]
    fn parses_components_and_filters() {
        let manifest = parse_manifest_bytes(SAMPLE.as_bytes()).unwrap();
        let activity = manifest
            .components
            .iter()
            .find(|c| c.kind == ComponentKind::Activity)
            .expect("activity parsed");
        assert_eq!(activity.exported, Some(true));
        let deeplink = activity
            .intent_filters
            .iter()
            .find(|f| f.is_browseable_deeplink())
            .expect("deeplink filter");
        assert_eq!(deeplink.schemes, vec!["lyft"]);
    }

    #[test]
    fn receiver_inferred_exported_via_intent_filter() {
        let manifest = parse_manifest_bytes(SAMPLE.as_bytes()).unwrap();
        let receiver = manifest
            .components
            .iter()
            .find(|c| c.kind == ComponentKind::Receiver)
            .expect("receiver parsed");
        assert_eq!(receiver.exported, None);
        assert!(receiver.is_effectively_exported());
    }
}
