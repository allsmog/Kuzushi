use super::*;

pub(super) fn inspect(inspection: &NodeLineInspection<'_>, builder: &mut AttackSurfaceBuilder) {
    if !inspection.has_any(&[
        "multer(",
        "upload.single(",
        "upload.array(",
        "upload.fields(",
        "busboy(",
        "formidable(",
        "multipart",
        "parsemultipart",
    ]) {
        return;
    }

    let route = inspection.route();
    inspection.add_surface(
        builder,
        AttackSurfaceKind::FileUploadParsePath,
        "File upload or multipart parser",
        route.method.as_deref(),
        route.path.as_deref(),
        Some("file_input"),
        "node.file-upload",
    );
}
