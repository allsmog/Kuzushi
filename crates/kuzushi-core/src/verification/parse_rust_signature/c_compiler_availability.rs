use super::*;

#[derive(Debug, Clone, Copy)]
pub(in crate::verification) struct CCompilerAvailability {
    pub(in crate::verification) preferred: &'static str,
    pub(in crate::verification) fallback: &'static str,
    pub(in crate::verification) preferred_present: bool,
    pub(in crate::verification) fallback_present: bool,
    pub(in crate::verification) preferred_has_asan: bool,
    pub(in crate::verification) fallback_has_asan: bool,
}

impl CCompilerAvailability {
    pub(in crate::verification) fn detect(compiler: CCompiler) -> Self {
        Self {
            preferred: compiler.binary(),
            fallback: compiler.fallback(),
            preferred_present: kuzushi_sandbox::which(compiler.binary()).is_some(),
            fallback_present: kuzushi_sandbox::which(compiler.fallback()).is_some(),
            preferred_has_asan: clang_asan_runtime_present(),
            fallback_has_asan: gcc_asan_runtime_present(),
        }
    }

    pub(in crate::verification) fn pick(self) -> Option<String> {
        self.pick_with_asan().or_else(|| self.pick_available())
    }

    fn pick_with_asan(self) -> Option<String> {
        self.pick_if(
            self.preferred,
            self.preferred_present && self.preferred_has_asan,
        )
        .or_else(|| {
            self.pick_if(
                self.fallback,
                self.fallback_present && self.fallback_has_asan,
            )
        })
    }

    fn pick_available(self) -> Option<String> {
        self.pick_if(self.preferred, self.preferred_present)
            .or_else(|| self.pick_if(self.fallback, self.fallback_present))
    }

    fn pick_if(self, binary: &str, available: bool) -> Option<String> {
        available.then(|| binary.to_string())
    }
}

pub(in crate::verification) fn clang_asan_runtime_present() -> bool {
    let candidates = [
        "/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.asan-x86_64.a",
        "/usr/lib/llvm-17/lib/clang/17/lib/linux/libclang_rt.asan-x86_64.a",
        "/usr/lib/llvm-16/lib/clang/16/lib/linux/libclang_rt.asan-x86_64.a",
        "/usr/lib/clang/18/lib/linux/libclang_rt.asan-x86_64.a",
        "/usr/local/lib/clang/18/lib/linux/libclang_rt.asan-x86_64.a",
    ];
    candidates.iter().any(|p| std::path::Path::new(p).exists())
}

pub(in crate::verification) fn gcc_asan_runtime_present() -> bool {
    let candidates = [
        "/usr/lib/gcc/x86_64-linux-gnu/13/libasan.a",
        "/usr/lib/gcc/x86_64-linux-gnu/13/libasan.so",
        "/usr/lib/gcc/x86_64-linux-gnu/14/libasan.a",
        "/usr/lib/gcc/x86_64-linux-gnu/14/libasan.so",
        "/usr/lib/gcc/x86_64-linux-gnu/12/libasan.a",
        "/usr/lib/x86_64-linux-gnu/libasan.so.8",
        "/usr/lib/x86_64-linux-gnu/libasan.so.6",
    ];
    candidates.iter().any(|p| std::path::Path::new(p).exists())
}

/// Pick sanitizer flags conditional on toolchain availability. Returns
/// an empty vec when no ASan runtime is present so the harness still
/// builds and runs (weaker detection but the pipeline keeps working).
pub(in crate::verification) fn c_sanitizer_flags(compiler: &str) -> Vec<&'static str> {
    let runtime_present = if compiler.starts_with("clang") {
        clang_asan_runtime_present()
    } else if compiler.starts_with("gcc") || compiler.starts_with("g++") {
        gcc_asan_runtime_present()
    } else {
        false
    };
    if runtime_present {
        vec!["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    } else {
        Vec::new()
    }
}
