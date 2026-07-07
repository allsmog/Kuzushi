use super::{
    plugin_manifest_json, validate_plugin_stdout, GrantedSnapshot, PluginSandboxBackend,
    PluginSandboxResult, SandboxPolicy,
};
use crate::identity::Blake3Hash;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use wasmtime::{
    Caller, Config, Engine, Extern, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};

const ABI_MODULE: &str = "kuzushi";
const ANALYZE_EXPORT: &str = "kuzushi_analyze";
const MEMORY_EXPORT: &str = "memory";
const WASM_PAGE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmPluginInvocation {
    pub module_path: PathBuf,
    pub policy: SandboxPolicy,
    pub grant: GrantedSnapshot,
}

pub fn run_wasm_plugin_invocation(invocation: WasmPluginInvocation) -> Result<PluginSandboxResult> {
    validate_wasm_policy(&invocation)?;
    let started = Instant::now();
    let engine = wasm_engine()?;
    let module = Module::from_file(&engine, &invocation.module_path).with_context(|| {
        format!(
            "Could not compile Wasm plugin {}",
            invocation.module_path.display()
        )
    })?;
    let mut store = wasm_store(&engine, &invocation)?;
    let mut linker = Linker::new(&engine);
    register_host_imports(&mut linker)?;
    let instance = linker
        .instantiate(&mut store, &module)
        .context("Could not instantiate Wasm plugin")?;
    require_memory_within_limit(&mut store, &instance, invocation.policy.memory_limit_bytes)?;
    let analyze = instance
        .get_typed_func::<(), i64>(&mut store, ANALYZE_EXPORT)
        .context("Wasm plugin must export kuzushi_analyze() -> i64")?;
    let packed_output = analyze
        .call(&mut store, ())
        .context("Wasm plugin analyze export trapped")?;
    let stdout = read_guest_output(
        &mut store,
        &instance,
        packed_output,
        invocation.policy.max_output_bytes,
    )?;
    let findings = validate_plugin_stdout(&stdout, &invocation.grant, &invocation.policy)?;
    Ok(PluginSandboxResult {
        backend: PluginSandboxBackend::Wasmtime,
        duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        findings,
    })
}

fn validate_wasm_policy(invocation: &WasmPluginInvocation) -> Result<()> {
    super::policy_validation::validate_sandbox_policy(&invocation.policy)?;
    if invocation.module_path.as_os_str().is_empty() {
        bail!("Wasm plugin path cannot be empty");
    }
    Ok(())
}

fn wasm_engine() -> Result<Engine> {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.signals_based_traps(false);
    config.wasm_backtrace(false);
    Engine::new(&config).context("Could not initialize Wasmtime engine")
}

fn wasm_store(engine: &Engine, invocation: &WasmPluginInvocation) -> Result<Store<WasmHostState>> {
    let manifest = plugin_manifest_json(&invocation.grant, false)?;
    let limits = StoreLimitsBuilder::new()
        .memory_size(invocation.policy.memory_limit_bytes as usize)
        .instances(1)
        .memories(1)
        .tables(1)
        .build();
    let mut store = Store::new(
        engine,
        WasmHostState {
            grant: invocation.grant.clone(),
            manifest: manifest.into_bytes(),
            max_bytes_served: invocation.policy.max_bytes_served,
            bytes_served: 0,
            limits,
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(invocation.policy.fuel_limit)
        .context("Could not set Wasm fuel limit")?;
    Ok(store)
}

fn register_host_imports(linker: &mut Linker<WasmHostState>) -> Result<()> {
    linker.func_wrap(ABI_MODULE, "manifest_len", manifest_len)?;
    linker.func_wrap(ABI_MODULE, "manifest_read", manifest_read)?;
    linker.func_wrap(ABI_MODULE, "blob_len", blob_len)?;
    linker.func_wrap(ABI_MODULE, "blob_read", blob_read)?;
    Ok(())
}

fn require_memory_within_limit(
    store: &mut Store<WasmHostState>,
    instance: &wasmtime::Instance,
    limit_bytes: u64,
) -> Result<()> {
    let memory = guest_memory(store, instance)?;
    let current_bytes = memory.size(&mut *store).saturating_mul(WASM_PAGE_BYTES);
    if current_bytes > limit_bytes {
        bail!("Wasm plugin memory exceeds policy limit");
    }
    Ok(())
}

fn read_guest_output(
    store: &mut Store<WasmHostState>,
    instance: &wasmtime::Instance,
    packed: i64,
    max_output_bytes: u64,
) -> Result<String> {
    let ptr = (packed as u64 & 0xffff_ffff) as usize;
    let len = ((packed as u64) >> 32) as usize;
    if len == 0 {
        bail!("Wasm plugin returned an empty output buffer");
    }
    if len as u64 > max_output_bytes {
        bail!("Wasm plugin output exceeds policy cap");
    }
    let mut bytes = vec![0; len];
    guest_memory(store, instance)?
        .read(&mut *store, ptr, &mut bytes)
        .context("Wasm plugin returned an invalid output pointer")?;
    String::from_utf8(bytes).context("Wasm plugin output must be UTF-8 JSON")
}

fn guest_memory(store: &mut Store<WasmHostState>, instance: &wasmtime::Instance) -> Result<Memory> {
    instance
        .get_memory(&mut *store, MEMORY_EXPORT)
        .context("Wasm plugin must export memory")
}

struct WasmHostState {
    grant: GrantedSnapshot,
    manifest: Vec<u8>,
    max_bytes_served: u64,
    bytes_served: u64,
    limits: StoreLimits,
}

fn manifest_len(caller: Caller<'_, WasmHostState>) -> i32 {
    i32::try_from(caller.data().manifest.len()).unwrap_or(i32::MAX)
}

fn manifest_read(mut caller: Caller<'_, WasmHostState>, ptr: i32, max_len: i32) -> i32 {
    let len = caller.data().manifest.len().min(max_len.max(0) as usize);
    let bytes = caller.data().manifest[..len].to_vec();
    write_guest_memory(&mut caller, ptr, &bytes)
}

fn blob_len(mut caller: Caller<'_, WasmHostState>, hash_ptr: i32, hash_len: i32) -> i64 {
    let Ok(hash) = read_guest_hash(&mut caller, hash_ptr, hash_len) else {
        return -1;
    };
    caller
        .data()
        .grant
        .blob_size(&hash)
        .and_then(|size| i64::try_from(size).ok())
        .unwrap_or(-1)
}

fn blob_read(
    mut caller: Caller<'_, WasmHostState>,
    hash_ptr: i32,
    hash_len: i32,
    offset: i64,
    dst_ptr: i32,
    max_len: i32,
) -> i32 {
    let Ok(hash) = read_guest_hash(&mut caller, hash_ptr, hash_len) else {
        return -1;
    };
    let Ok(bytes) = read_granted_blob(&caller, &hash) else {
        return -1;
    };
    let offset = offset.max(0) as usize;
    if offset >= bytes.len() {
        return 0;
    }
    let len = bytes[offset..].len().min(max_len.max(0) as usize);
    if !reserve_served_bytes(caller.data_mut(), len as u64) {
        return -1;
    }
    write_guest_memory(&mut caller, dst_ptr, &bytes[offset..offset + len])
}

fn read_guest_hash(
    caller: &mut Caller<'_, WasmHostState>,
    hash_ptr: i32,
    hash_len: i32,
) -> Result<Blake3Hash> {
    let hash = read_guest_bytes(caller, hash_ptr, hash_len)?;
    let text = String::from_utf8(hash).context("blob hash import argument must be UTF-8")?;
    Blake3Hash::new(text)
}

fn read_guest_bytes(caller: &mut Caller<'_, WasmHostState>, ptr: i32, len: i32) -> Result<Vec<u8>> {
    let len = usize::try_from(len).context("guest length must be non-negative")?;
    let ptr = usize::try_from(ptr).context("guest pointer must be non-negative")?;
    let mut bytes = vec![0; len];
    memory_from_caller(caller)?
        .read(&mut *caller, ptr, &mut bytes)
        .context("guest pointer was outside memory")?;
    Ok(bytes)
}

fn write_guest_memory(caller: &mut Caller<'_, WasmHostState>, ptr: i32, bytes: &[u8]) -> i32 {
    let Ok(ptr) = usize::try_from(ptr) else {
        return -1;
    };
    match memory_from_caller(caller).and_then(|memory| {
        memory
            .write(&mut *caller, ptr, bytes)
            .context("guest destination pointer was outside memory")
    }) {
        Ok(()) => i32::try_from(bytes.len()).unwrap_or(i32::MAX),
        Err(_) => -1,
    }
}

fn memory_from_caller(caller: &mut Caller<'_, WasmHostState>) -> Result<Memory> {
    match caller.get_export(MEMORY_EXPORT) {
        Some(Extern::Memory(memory)) => Ok(memory),
        _ => bail!("Wasm plugin must export memory"),
    }
}

fn read_granted_blob(caller: &Caller<'_, WasmHostState>, hash: &Blake3Hash) -> Result<Vec<u8>> {
    let path = caller
        .data()
        .grant
        .object_path(hash)
        .with_context(|| format!("blob {hash} has no granted CAS object path"))?;
    fs::read(path).with_context(|| format!("Could not read granted blob {}", path.display()))
}

fn reserve_served_bytes(state: &mut WasmHostState, next: u64) -> bool {
    let Some(total) = state.bytes_served.checked_add(next) else {
        return false;
    };
    if total > state.max_bytes_served {
        return false;
    }
    state.bytes_served = total;
    true
}
