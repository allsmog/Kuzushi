use super::*;

pub(in crate::modules) fn android_apk_module() -> BuiltinModule {
    builtin_module(
        "android-apk",
        "Android APK",
        ModuleKind::Defense,
        "Unpack, decompile, and analyze Android APKs so Kuzushi's existing Java/Kotlin SAST engines can run against the decompiled source and Kuzushi can emit Android-framework-aware findings.",
        vec![
            check_env_tool().with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Optional)),
            prepare_tool().with_policy(target_write_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Optional)),
            manifest_scan_tool().with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Required)),
            network_security_config_tool().with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Required)),
            fileprovider_scan_tool().with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Required)),
            code_scan_tool().with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Required)),
            sast_handoff_tool().with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Optional)),
            native_libs_tool().with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Required)),
            hybrid_detect_tool().with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Required)),
            scan_tool().with_policy(target_write_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Required)),
        ],
        vec![],
    )
    .labs()
}

fn native_libs_tool() -> ToolDescriptor {
    hidden_tool_with_options(
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
            .workspace_read()
            .advanced(),
        ],
    )
}

fn scan_tool() -> ToolDescriptor {
    let mut options = apk_prepare_options();
    options.push(semgrep_binary_option());
    options.push(include_libraries_option());
    options.extend(apk_scan_options());
    tool_with_options(
        "android-apk:scan",
        "Experimental APK preparation and configuration/code observations. Requires explicit write consent. Decompilation accuracy and complete APK or repository coverage remain unqualified; results require review and do not complete Scan.",
        options,
    )
    .with_discovery_maturity(ModuleMaturity::Labs)
    .without_phase_result()
}

fn apk_scan_options() -> Vec<OptionSpec> {
    vec![
            opt(
                "runId",
                OptionType::String,
                "Internal parent run artifact id supplied by scan-mode dispatch.",
            )
            .aliases(&["run_id"])
            .advanced(),
            opt(
                "skipCode",
                OptionType::Bool,
                "Skip the bundled Semgrep code-scan rule pack (saves runtime if semgrep isn't installed). Alias: skipWebview.",
            )
            .aliases(&["skipWebview"])
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
        ]
}

fn hybrid_detect_tool() -> ToolDescriptor {
    hidden_tool_with_options(
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
            .workspace_read()
            .advanced(),
        ],
    )
}

fn code_scan_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "android-apk:code-scan",
        "Run the bundled Android Semgrep rule pack against the decompiled jadx source tree. Covers WebView/JS-bridge misuse, intent redirection, mutable PendingIntent, ECB/MD5/SHA-1/static-IV crypto misuse, PII logging, clipboard credential exposure, MODE_WORLD_* file modes, plaintext SharedPreferences, HostnameVerifier/X509TrustManager all-accept patterns, SQL injection via rawQuery/execSQL string concat, deeplink URI loaded into WebView, reflection on Intent extras, intent redirection through extras, and Keystore-misuse patterns (RSA PKCS1, no user auth, hardcoded SecretKeySpec). Writes a .semgrepignore in the scan root that filters out gms / androidx / kotlin / okhttp / retrofit / react-native / dagger noise; pass includeLibraries=true to disable.",
        vec![
            target_option(),
            opt(
                "jadxDir",
                OptionType::Path,
                "Override path to the decompiled jadx sources directory. Defaults to <target>/android-decompiled/jadx/sources.",
            )
            .aliases(&["jadx_dir"])
            .workspace_read()
            .advanced(),
            include_libraries_option(),
            binary_option("Semgrep binary path."),
            apk_timeout_option(),
        ],
    )
}

fn sast_handoff_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "android-apk:sast-handoff",
        "Bridge node that returns the decompiled tree layout (jadx/apktool/raw paths, taint-sources.json) so downstream Java SAST engines can be invoked against the right roots. Emits next-step commands; warns when prepare/manifest-scan haven't run yet.",
        vec![target_option()],
    )
}

fn manifest_scan_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "android-apk:manifest-scan",
        "Parse AndroidManifest.xml emitted by apktool and emit findings for debuggable, allowBackup, cleartext, exported components without permission, deep links, and provider exposure. Writes taint-sources.json next to the manifest for downstream consumption.",
        vec![target_option(), decompiled_root_option()],
    )
}

fn network_security_config_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "android-apk:network-security-config",
        "Parse res/xml/network_security_config.xml and emit findings for cleartext-permitted base/domain configs and user-CA trust anchors.",
        vec![target_option(), nsc_path_option()],
    )
}

fn fileprovider_scan_tool() -> ToolDescriptor {
    hidden_tool_with_options(
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
    .workspace_read()
    .advanced()
}

fn nsc_path_option() -> OptionSpec {
    opt(
        "configPath",
        OptionType::Path,
        "Override path to network_security_config.xml. Defaults to <target>/android-decompiled/apktool/res/xml/network_security_config.xml.",
    )
    .aliases(&["config_path"])
    .workspace_read()
    .advanced()
}

fn file_paths_option() -> OptionSpec {
    opt(
        "filePathsPath",
        OptionType::Path,
        "Override path to file_paths.xml. Defaults to <target>/android-decompiled/apktool/res/xml/file_paths.xml.",
    )
    .aliases(&["file_paths_path"])
    .workspace_read()
    .advanced()
}

fn check_env_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "android-apk:check-env",
        "Verify that jadx, apktool, and unzip are available on PATH.",
        vec![jadx_bin_option(), apktool_bin_option(), unzip_bin_option()],
    )
}

fn prepare_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "android-apk:prepare",
        "Validate an APK file, unzip resources, and decompile to Java source under <workspace>/android-decompiled/.",
        apk_prepare_options(),
    )
}

fn apk_prepare_options() -> Vec<OptionSpec> {
    vec![
        apk_option(),
        decompiler_option(),
        jadx_bin_option(),
        apktool_bin_option(),
        unzip_bin_option(),
        apk_timeout_option(),
        max_apk_bytes_option(),
        target_option(),
    ]
}

fn include_libraries_option() -> OptionSpec {
    opt("includeLibraries", OptionType::Bool, "Include library packages in bundled code-rule scanning. Otherwise .semgrepignore excludes common libraries; omitted material is not complete APK coverage.")
        .default(json!(false))
        .advanced()
}

fn max_apk_bytes_option() -> OptionSpec {
    opt("maxApkBytes", OptionType::Int, "Maximum archive bytes inspected for input provenance. Default 512 MiB, maximum 4 GiB; oversized input is refused before extraction.")
        .aliases(&["max_apk_bytes"])
        .integer_range(1, android_apk_input_receipt::MAX_APK_BYTES as i64)
        .default(json!(android_apk_input_receipt::DEFAULT_APK_BYTES))
        .advanced()
}

fn semgrep_binary_option() -> OptionSpec {
    opt(
        "semgrepBin",
        OptionType::Path,
        "Executable for the bundled Android code rules.",
    )
    .aliases(&["semgrep_bin"])
    .executable()
    .advanced()
}

fn apk_option() -> OptionSpec {
    opt(
        "apk",
        OptionType::Path,
        "Path to the APK archive. The content digest identifies supplied bytes; decompiled locations still require independent review.",
    )
    .aliases(&["apkPath", "apk_path", "file"])
    .external_read()
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

fn apk_timeout_option() -> OptionSpec {
    opt(
        "timeoutMs",
        OptionType::Int,
        "Per unzip/decompiler/code-scan process deadline in milliseconds, from 1 to 86400000. Several processes can run in an APK action; this is not a whole-operation deadline.",
    )
    .aliases(&["timeout_ms"])
    .default(json!(DEFAULT_ANDROID_COMMAND_TIMEOUT_MS))
    .integer_range(1, MAX_ANDROID_COMMAND_TIMEOUT_MS as i64)
    .advanced()
}

fn jadx_bin_option() -> OptionSpec {
    opt("jadxBin", OptionType::Path, "Path to the jadx binary.")
        .aliases(&["jadx_bin", "jadx"])
        .executable()
        .advanced()
}

fn apktool_bin_option() -> OptionSpec {
    opt(
        "apktoolBin",
        OptionType::Path,
        "Path to the apktool binary.",
    )
    .aliases(&["apktool_bin", "apktool"])
    .executable()
    .advanced()
}

fn unzip_bin_option() -> OptionSpec {
    opt("unzipBin", OptionType::Path, "Path to the unzip binary.")
        .aliases(&["unzip_bin", "unzip"])
        .executable()
        .advanced()
}
