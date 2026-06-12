use super::*;

use quick_xml::events::BytesStart;

#[derive(Debug, Default)]
pub(in crate::modules) struct ParserState {
    manifest: ParsedManifest,
    stack: Vec<String>,
    current_component: Option<Component>,
    current_filter: Option<IntentFilter>,
}

impl ParserState {
    pub(in crate::modules) fn on_open(&mut self, element: &BytesStart<'_>) -> Result<()> {
        let local = element_local_name(element);
        if let Some(kind) = component_kind_for(&local) {
            self.start_component(kind, element)?;
        } else {
            self.dispatch_non_component(&local, element)?;
        }
        self.stack.push(local);
        Ok(())
    }

    fn dispatch_non_component(&mut self, local: &str, element: &BytesStart<'_>) -> Result<()> {
        match local {
            "manifest" => self.read_manifest_attrs(element),
            "uses-sdk" => self.read_uses_sdk(element),
            "application" => self.read_application(element),
            "uses-permission" => self.read_uses_permission(element),
            "intent-filter" => {
                self.current_filter = Some(IntentFilter::default());
                Ok(())
            }
            "action" => self.read_filter_value(element, FilterField::Action),
            "category" => self.read_filter_value(element, FilterField::Category),
            "data" => self.read_filter_data(element),
            _ => Ok(()),
        }
    }

    pub(in crate::modules) fn on_close(&mut self, element: &BytesStart<'_>) {
        let local = element_local_name(element);
        self.finalize_close(&local);
    }

    pub(in crate::modules) fn on_close_owned(&mut self, element: &quick_xml::events::BytesEnd<'_>) {
        let name = String::from_utf8_lossy(element.name().as_ref()).to_string();
        let local = name.rsplit_once(':').map(|(_, l)| l.to_string()).unwrap_or(name);
        self.finalize_close(&local);
    }

    fn finalize_close(&mut self, local: &str) {
        if local == "intent-filter" {
            self.flush_intent_filter();
        } else if is_component_tag(local) {
            self.flush_component();
        }
        if self.stack.last().map(String::as_str) == Some(local) {
            self.stack.pop();
        }
    }

    fn flush_intent_filter(&mut self) {
        if let (Some(filter), Some(component)) = (
            self.current_filter.take(),
            self.current_component.as_mut(),
        ) {
            component.intent_filters.push(filter);
        }
    }

    fn flush_component(&mut self) {
        if let Some(component) = self.current_component.take() {
            self.manifest.components.push(component);
        }
    }

    pub(in crate::modules) fn finish(self) -> ParsedManifest {
        self.manifest
    }

    fn read_manifest_attrs(&mut self, element: &BytesStart<'_>) -> Result<()> {
        if let Some(package) = attr_value(element, "package")? {
            self.manifest.package = Some(package);
        }
        Ok(())
    }

    fn read_uses_sdk(&mut self, element: &BytesStart<'_>) -> Result<()> {
        if let Some(value) = attr_value(element, "android:targetSdkVersion")? {
            if let Ok(parsed) = value.parse::<u32>() {
                self.manifest.target_sdk = Some(parsed);
            }
        }
        Ok(())
    }

    fn read_application(&mut self, element: &BytesStart<'_>) -> Result<()> {
        self.manifest.application = ApplicationAttrs {
            debuggable: attr_bool(element, "android:debuggable")?,
            allow_backup: attr_bool(element, "android:allowBackup")?,
            uses_cleartext_traffic: attr_bool(element, "android:usesCleartextTraffic")?,
        };
        Ok(())
    }

    fn read_uses_permission(&mut self, element: &BytesStart<'_>) -> Result<()> {
        if let Some(name) = attr_value(element, "android:name")? {
            self.manifest.permissions.push(name);
        }
        Ok(())
    }

    fn start_component(&mut self, kind: ComponentKind, element: &BytesStart<'_>) -> Result<()> {
        self.current_component = Some(Component {
            kind,
            name: attr_value(element, "android:name")?.unwrap_or_default(),
            exported: attr_bool(element, "android:exported")?,
            permission: attr_value(element, "android:permission")?,
            grant_uri_permissions: attr_bool(element, "android:grantUriPermissions")?,
            intent_filters: Vec::new(),
        });
        Ok(())
    }

    fn read_filter_value(&mut self, element: &BytesStart<'_>, field: FilterField) -> Result<()> {
        let value = match attr_value(element, "android:name")? {
            Some(value) => value,
            None => return Ok(()),
        };
        if let Some(filter) = self.current_filter.as_mut() {
            push_filter_value(filter, field, value);
        }
        Ok(())
    }

    fn read_filter_data(&mut self, element: &BytesStart<'_>) -> Result<()> {
        let scheme = attr_value(element, "android:scheme")?;
        let host = attr_value(element, "android:host")?;
        if let Some(filter) = self.current_filter.as_mut() {
            if let Some(scheme) = scheme {
                filter.schemes.push(scheme);
            }
            if let Some(host) = host {
                filter.hosts.push(host);
            }
        }
        Ok(())
    }
}

fn push_filter_value(filter: &mut IntentFilter, field: FilterField, value: String) {
    match field {
        FilterField::Action => filter.actions.push(value),
        FilterField::Category => filter.categories.push(value),
    }
}

#[derive(Debug, Clone, Copy)]
enum FilterField {
    Action,
    Category,
}

fn component_kind_for(local: &str) -> Option<ComponentKind> {
    match local {
        "activity" => Some(ComponentKind::Activity),
        "activity-alias" => Some(ComponentKind::ActivityAlias),
        "service" => Some(ComponentKind::Service),
        "receiver" => Some(ComponentKind::Receiver),
        "provider" => Some(ComponentKind::Provider),
        _ => None,
    }
}

fn is_component_tag(local: &str) -> bool {
    component_kind_for(local).is_some()
}

pub(in crate::modules) fn element_local_name(element: &BytesStart<'_>) -> String {
    let name = String::from_utf8_lossy(element.name().as_ref()).to_string();
    name.rsplit_once(':')
        .map(|(_, local)| local.to_string())
        .unwrap_or(name)
}

pub(in crate::modules) fn attr_value(
    element: &BytesStart<'_>,
    qualified: &str,
) -> Result<Option<String>> {
    for attr in element.attributes() {
        let attr = attr?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        if attr_matches(&key, qualified) {
            return Ok(Some(String::from_utf8_lossy(attr.value.as_ref()).to_string()));
        }
    }
    Ok(None)
}

fn attr_matches(key: &str, qualified: &str) -> bool {
    key == qualified || key.ends_with(qualified) || strip_ns(key) == strip_ns(qualified)
}

fn strip_ns(name: &str) -> &str {
    name.rsplit_once(':').map(|(_, l)| l).unwrap_or(name)
}

pub(in crate::modules) fn attr_bool(
    element: &BytesStart<'_>,
    qualified: &str,
) -> Result<Option<bool>> {
    Ok(attr_value(element, qualified)?.and_then(|value| parse_bool(&value)))
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" | "True" | "TRUE" | "1" => Some(true),
        "false" | "False" | "FALSE" | "0" => Some(false),
        _ => None,
    }
}
