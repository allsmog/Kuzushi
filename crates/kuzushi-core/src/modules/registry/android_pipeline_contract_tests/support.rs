use crate::{FindingStore, ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::path::PathBuf;

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    pub workspace: WorkspaceTarget,
    pub apk: PathBuf,
    pub cancel: crate::scan::ScanCancellation,
    pub store: FindingStore,
    config: V2Config,
}

impl Fixture {
    pub fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(
            target.join("hello.txt"),
            "Owned inert source. Never executed.\n",
        )
        .unwrap();
        let apk = root.path().join("owned.apk");
        let mut bytes = vec![b'P', b'K', 3, 4];
        bytes.extend([0; 26]);
        std::fs::write(&apk, bytes).unwrap();
        let workspace = WorkspaceTarget::new(&target).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        Self {
            _root: root,
            workspace,
            apk,
            store,
            cancel: Default::default(),
            config: Default::default(),
        }
    }

    #[cfg(unix)]
    pub fn script(&self, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = self.apk.parent().unwrap().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(unix)]
    pub fn input(&self) -> Value {
        json!({"apk":self.apk,"decompiler":"both","timeoutMs":2000,"maxApkBytes":1024,
            "unzipBin":self.script("owned-unzip",UNZIP),"jadxBin":self.script("owned-jadx",JADX),
            "apktoolBin":self.script("owned-apktool",APKTOOL),
            "semgrepBin":self.script("owned-semgrep",r#"printf '{"results":[],"errors":[]}'"#)})
    }

    pub fn dispatch(&self, value: Value, authorize: bool) -> anyhow::Result<Value> {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation: Some(&self.cancel),
            authorization: Default::default(),
        };
        let mut prepared =
            registry.prepare_dispatch_input("android-apk:scan", value, &ctx, None)?;
        if authorize {
            prepared = prepared.authorize_explicit_headless();
        }
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
    }
}

#[cfg(unix)]
const UNZIP: &str = r#"
if [ "$1" = '-l' ]; then
  printf 'Archive: owned fixture\n Length Date Time Name\n---------\n 4 2026-10-14 00:00 owned.txt\n---------\n'; exit 0
fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-d' ]; then shift; out="$1"; fi
  shift
done
mkdir -p "$out"; printf 'Owned raw text' > "$out/owned.txt"
"#;

#[cfg(unix)]
const JADX: &str = r#"
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-d' ]; then shift; out="$1"; fi
  shift
done
mkdir -p "$out/sources"; printf '// Owned derived text. Never executed.\n' > "$out/sources/Owned.java"
"#;

#[cfg(unix)]
pub(super) const APKTOOL: &str = r#"
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-o' ]; then shift; out="$1"; fi
  shift
done
mkdir -p "$out"
printf '%s\n' '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="owned.greeting"><application android:debuggable="true" android:allowBackup="false" android:usesCleartextTraffic="false"/></manifest>' > "$out/AndroidManifest.xml"
"#;
