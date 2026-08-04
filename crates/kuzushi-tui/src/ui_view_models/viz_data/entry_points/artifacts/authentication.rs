use super::fields::ReceiptFields;
use super::ArtifactDocument;
use crate::app::EntryPointCatalogContextAuthentication;
use crate::ui_view_models::EntryPointArtifactStatus;
use serde_json::Value;

pub(super) fn authenticate_catalog(
    catalog: &ArtifactDocument,
    fields: &mut ReceiptFields,
    warnings: &mut Vec<String>,
) -> bool {
    let Some(document) = catalog.doc() else {
        fields.catalog_digest = None;
        return false;
    };
    if !catalog_declares_digest(document) {
        fields.catalog_digest = None;
        warnings.push("legacy catalog has no authenticated payload digest".to_string());
        return false;
    }
    apply_catalog_authentication(catalog, fields, warnings)
}

fn apply_catalog_authentication(
    catalog: &ArtifactDocument,
    fields: &mut ReceiptFields,
    warnings: &mut Vec<String>,
) -> bool {
    let Some(authentication) = catalog.catalog_authentication.clone() else {
        fields.catalog_digest = None;
        warnings.push("catalog authentication unavailable; freshness is unprovable".to_string());
        return false;
    };
    match authentication {
        Ok(authentication) => {
            fields.catalog_digest = Some(authentication.sha256);
            fields.snapshot_timestamp_ms = Some(authentication.snapshot_timestamp);
            true
        }
        Err(error) => {
            fields.catalog_digest = None;
            warnings.push(format!("catalog integrity failed: {error}"));
            false
        }
    }
}

pub(super) fn authenticate_catalog_context(
    catalog: &ArtifactDocument,
    catalog_authenticated: bool,
    fields: &mut ReceiptFields,
    warnings: &mut Vec<String>,
) -> Option<bool> {
    if !catalog_authenticated {
        return None;
    }
    match &catalog.catalog_context_authentication {
        Some(EntryPointCatalogContextAuthentication::Authenticated(authentication)) => {
            fields.catalog_context_digest = Some(authentication.context_sha256.clone());
            fields.catalog_tree_hash = authentication.tree_hash.clone();
            Some(true)
        }
        Some(EntryPointCatalogContextAuthentication::Rejected(error)) => {
            warnings.push(format!("catalog derivation rejected: {error}"));
            Some(false)
        }
        Some(EntryPointCatalogContextAuthentication::Unavailable(error)) => {
            warnings.push(format!("catalog derivation unavailable: {error}"));
            None
        }
        None => {
            warnings.push("catalog derivation authentication unavailable".to_string());
            None
        }
    }
}

pub(super) fn effective_catalog_status(
    catalog: &ArtifactDocument,
    authenticated: bool,
) -> EntryPointArtifactStatus {
    let failed_authentication = catalog
        .doc()
        .is_some_and(|document| catalog_declares_digest(document) && !authenticated);
    if failed_authentication {
        EntryPointArtifactStatus::Malformed
    } else {
        catalog.status
    }
}

fn catalog_declares_digest(document: &Value) -> bool {
    document
        .pointer("/provenance/sha256")
        .and_then(Value::as_str)
        .is_some_and(|digest| !digest.is_empty())
}
