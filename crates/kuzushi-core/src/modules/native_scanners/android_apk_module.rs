use super::*;

pub(in crate::modules) fn android_apk_module() -> BuiltinModule {
    builtin_module(
        "android-apk",
        "Android APK",
        ModuleKind::Defense,
        "Unpack, decompile, and analyze Android APKs so Kuzushi's existing Java/Kotlin SAST engines can run against the decompiled source and Kuzushi can emit Android-framework-aware findings.",
        vec![
            check_env_tool(),
            prepare_tool(),
            manifest_scan_tool(),
            network_security_config_tool(),
            fileprovider_scan_tool(),
            webview_scan_tool(),
            sast_handoff_tool(),
            native_libs_tool(),
            hybrid_detect_tool(),
            scan_tool(),
        ],
        vec![],
    )
}

fn native_libs_tool() -> ToolDescriptor {
    tool_with_options(
        "android-apk:native-libs",
        "Enumerate `.so` files under <workspace>/android-decompiled/raw/lib/<abi>/, parse their ELF dynsyms with goblin, and emit findings for dangerous imports (system/execve/dlopen/strcpy) and JNI export attack surface.",
        vec![
            target_option(),
            opt(
                "libRoot",
                OptionType::Path,
                "Override the lib/<abi>/ root. Defaults to <target>/android-decompiled/raw/lib.",
            )
            .aliases(&["lib_root"])
            .advanced(),
        ],
    )
}

fn scan_tool() -> ToolDescriptor {
    tool_with_options(
        "android-apk:scan",
        "Umbrella: validates the APK, decompiles it, then runs every android-apk:* scanner (manifest, network-security-config, fileprovider, webview, native-libs, hybrid-detect) and the sast-handoff bridge in one pass. Returns a per-stage summary so you can drill into individual results.",
        vec![
            apk_option(),
            decompiler_option(),
            target_option(),
            opt(
                "skipWebview",
                OptionType::Bool,
                "Skip the bundled Semgrep webview rule pack (saves runtime if semgrep isn't installed).",
            )
            .advanced(),
            opt(
                "skipNative",
                OptionType::Bool,
                "Skip native .so triage (saves runtime when the APK ships no lib/ directory).",
            )
            .advanced(),
            opt(
                "skipHybrid",
                OptionType::Bool,
                "Skip hybrid-app framework detection.",
            )
            .advanced(),
        ],
    )
}

fn hybrid_detect_tool() -> ToolDescriptor {
    tool_with_options(
        "android-apk:hybrid-detect",
        "Detect hybrid app frameworks (Cordova, React Native, Capacitor, Flutter, Ionic) by their on-disk fingerprints in the unzipped APK so you know which JavaScript / Dart bundles deserve a follow-up review.",
        vec![
            target_option(),
            opt(
                "rawRoot",
                OptionType::Path,
                "Override the unzipped APK root. Defaults to <target>/android-decompiled/raw.",
            )
            .aliases(&["raw_root"])
            .advanced(),
        ],
    )
}

fn webview_scan_tool() -> ToolDescriptor {
    tool_with_options(
        "android-apk:webview-scan",
        "Run a bundled semgrep rule pack tuned for Android WebView/JS-bridge, intent redirection, mutable PendingIntent, crypto misuse, PII logging, and clipboard credential exposure against the decompiled jadx source tree.",
        vec![
            target_option(),
            opt(
                "jadxDir",
                OptionType::Path,
                "Override path to the decompiled jadx sources directory. Defaults to <target>/android-decompiled/jadx/sources.",
            )
            .aliases(&["jadx_dir"])
            .advanced(),
            binary_option("Semgrep binary path."),
        ],
    )
}

fn sast_handoff_tool() -> ToolDescriptor {
    tool_with_options(
        "android-apk:sast-handoff",
        "Bridge node that returns the decompiled tree layout (jadx/apktool/raw paths, taint-sources.json) so downstream Java SAST engines can be invoked against the right roots. Emits next-step commands; warns when prepare/manifest-scan haven't run yet.",
        vec![target_option()],
    )
}

fn manifest_scan_tool() -> ToolDescriptor {
    tool_with_options(
        "android-apk:manifest-scan",
        "Parse AndroidManifest.xml emitted by apktool and emit findings for debuggable, allowBackup, cleartext, exported components without permission, deep links, and provider exposure. Writes taint-sources.json next to the manifest for downstream consumption.",
        vec![target_option(), decompiled_root_option()],
    )
}

fn network_security_config_tool() -> ToolDescriptor {
    tool_with_options(
        "android-apk:network-security-config",
        "Parse res/xml/network_security_config.xml and emit findings for cleartext-permitted base/domain configs and user-CA trust anchors.",
        vec![target_option(), nsc_path_option()],
    )
}

fn fileprovider_scan_tool() -> ToolDescriptor {
    tool_with_options(
        "android-apk:fileprovider-scan",
        "Parse res/xml/file_paths.xml and flag overly broad FileProvider path descriptors (root-path, broad external-path) that expose sensitive files via shared URIs.",
        vec![target_option(), file_paths_option()],
    )
}

fn decompiled_root_option() -> OptionSpec {
    opt(
        "decompiledRoot",
        OptionType::Path,
        "Override path to the android-decompiled/ root produced by android-apk:prepare. Defaults to <target>/android-decompiled.",
    )
    .aliases(&["decompiled_root"])
    .advanced()
}

fn nsc_path_option() -> OptionSpec {
    opt(
        "configPath",
        OptionType::Path,
        "Override path to network_security_config.xml. Defaults to <target>/android-decompiled/apktool/res/xml/network_security_config.xml.",
    )
    .aliases(&["config_path"])
    .advanced()
}

fn file_paths_option() -> OptionSpec {
    opt(
        "filePathsPath",
        OptionType::Path,
        "Override path to file_paths.xml. Defaults to <target>/android-decompiled/apktool/res/xml/file_paths.xml.",
    )
    .aliases(&["file_paths_path"])
    .advanced()
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
