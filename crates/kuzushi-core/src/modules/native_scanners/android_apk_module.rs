use super::*;

pub(in crate::modules) fn android_apk_module() -> BuiltinModule {
    builtin_module(
        "android-apk",
        "Android APK",
        ModuleKind::Defense,
        "Unpack and decompile Android APKs so Kuzushi's existing Java/Kotlin SAST engines can analyze the source tree.",
        vec![check_env_tool(), prepare_tool()],
        vec![],
    )
}

fn check_env_tool() -> ToolDescriptor {
    tool_with_options(
        "android-apk:check-env",
        "Verify that jadx, apktool, and unzip are available on PATH.",
        vec![
            jadx_bin_option(),
            apktool_bin_option(),
            unzip_bin_option(),
        ],
    )
}

fn prepare_tool() -> ToolDescriptor {
    tool_with_options(
        "android-apk:prepare",
        "Validate an APK file, unzip resources, and decompile to Java source under <workspace>/android-decompiled/.",
        vec![
            apk_option(),
            decompiler_option(),
            jadx_bin_option(),
            apktool_bin_option(),
            unzip_bin_option(),
            target_option(),
        ],
    )
}

fn apk_option() -> OptionSpec {
    opt(
        "apk",
        OptionType::Path,
        "Path to the .apk file to analyze. Operator is responsible for acquiring it (Play Store, APKMirror, sideload) within their HackerOne program's scope.",
    )
    .aliases(&["apkPath", "apk_path", "file"])
    .required()
}

fn decompiler_option() -> OptionSpec {
    opt(
        "decompiler",
        OptionType::Enum,
        "Which decompiler(s) to run. 'jadx' gives Java source; 'apktool' gives smali + decoded resources (including AndroidManifest.xml); 'both' produces both trees.",
    )
    .choices(&["jadx", "apktool", "both"])
    .default(json!("both"))
}

fn jadx_bin_option() -> OptionSpec {
    opt("jadxBin", OptionType::Path, "Path to the jadx binary.")
        .aliases(&["jadx_bin", "jadx"])
        .advanced()
}

fn apktool_bin_option() -> OptionSpec {
    opt("apktoolBin", OptionType::Path, "Path to the apktool binary.")
        .aliases(&["apktool_bin", "apktool"])
        .advanced()
}

fn unzip_bin_option() -> OptionSpec {
    opt("unzipBin", OptionType::Path, "Path to the unzip binary.")
        .aliases(&["unzip_bin", "unzip"])
        .advanced()
}
