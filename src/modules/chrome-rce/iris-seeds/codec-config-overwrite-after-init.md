# IRIS seed — codec config-overwrite after init (CVE-2023-5217)

You are running an IRIS-style CodeQL loop. Your job is to author CodeQL queries that find a specific class of memory-safety bug in image / video codec **encoders**, anchored to a verified historical CVE.

## Anchor CVE

**CVE-2023-5217 (libvpx VP8 encoder)** — September 2023, ITW, attribution to Clément Lecigne (Google TAG), used to install commercial spyware. Fixed in libvpx commit `3fbd1dc`.

## The vulnerable code shape

The libvpx VP8 encoder allocates per-thread row-tracking buffers at `vpx_codec_enc_init` time, sized as `f(mb_rows, multi_threaded)`. The `vpx_codec_enc_config_set` function (used to update encoder config mid-stream) blindly copied the entire new config struct on top of the old one:

```c
// vp8_cx_iface.c (pre-fix):
res = validate_config(ctx, &cfg, &vp8_cfg, 0);
if (!res) {
  ctx->cfg = cfg;             // overwrites EVERY field including multi_threaded
  set_vp8e_config(&ctx->oxcf, ctx->cfg, ctx->vp8_cfg, mr_cfg);
  vp8_change_config(ctx->cpi, &ctx->oxcf);
}
```

If a caller sent an updated config that **increased `g_h`** (frame height → more `mb_rows`) AND **decreased `g_threads` from `>1` to `1`**, two things happened:
1. `vp8_change_config` had a realloc gate that only fires when `multi_threaded > 1`. The decreased thread count skipped the realloc.
2. Subsequent encoding wrote into the previously-allocated row buffer using the now-larger `mb_rows` count → linear OOB heap write.

The fix preserves the original `multi_threaded` value when init has already run:

```c
if (cpi->initial_width) {
  oxcf->multi_threaded = cpi->oxcf.multi_threaded;
}
```

Generalising: **a session/codec config struct used to size internal buffers at init time can be overwritten mid-stream by a `*_set_config` / `*_reconfigure` API, without re-running the buffer-sizing logic that was gated on the original values.**

## The bug class

Three things must coincide:

1. A C struct (`<X>_config_t`, `<X>_cfg_t`, `<codec>_oxcf_t`, etc.) holds buffer-sizing fields used at **init time** to allocate internal arrays whose dimensions are computed from those fields.
2. A `*_set_config` / `*_reconfigure` / `*_update_config` API performs a **whole-struct assignment** of the new config onto the session, e.g. `ctx->cfg = new_cfg` or `*ctx = *new_ctx`.
3. The downstream code that resizes internal buffers has **gating conditions on specific fields** of the old config (e.g. `if (multi_threaded > 1) realloc(...)`). When the new config disables those fields but increases the buffer-sizing dimensions, the realloc is skipped → next write is OOB.

This pattern shows up in:
- libvpx VP8 / VP9 (anchor CVE).
- libaom AV1 (analogous reconfigure paths).
- Any codec encoder that supports config updates between frames.

## Your job

Write CodeQL queries that find candidate sites. Iterate until queries compile and return ≥ 1 result.

### Query A — config-overwrite assignments

Find assignment expressions of the form `<session>->cfg = <new>` or `*<session> = *<new>` or `memcpy(<session>->cfg, <new>, sizeof(<T>))` inside functions named `*_set_config`, `*_config_set`, `*_reconfigure`, `*_update_config`, `*_change_config` (case-insensitive substring on the function name).

Bind `<session>` and `<new>` as metavariables. Restrict to files under `third_party/{libvpx,libaom,libwebp,dav1d,libavif}/**` or `media/**`.

### Query B — fields used to size internal buffers

For each session struct field referenced in Query A, find allocation sites in the same file (or library) whose size argument multiplies that field — e.g. `malloc(sizeof(<U>) * cfg.<field>)` or `calloc(cfg.<rows>, cfg.<cols>)`. Bind those fields as **buffer-sizing fields**.

### Query C — gating conditions on different fields

Find code paths that re-allocate the internal buffer (i.e. they call `realloc` / `*_alloc` on the buffer) gated on **a different field of the same struct** — pattern `if (cfg.<other_field> > <threshold>) { realloc(...); }`.

### Query D — the unsafe combination

The bug fires when:
- Query A's overwrite touches a buffer-sizing field (Query B).
- Query A's overwrite ALSO touches a gating field (Query C).
- The gate field can be lowered while the buffer-sizing field is raised, and there's no `is_initialized` / `created` flag check before the overwrite.

Surface this as a finding with the assignment site as the primary location and the alloc + gate sites as secondary "evidence" locations.

### Query E — `is_initialized` check (the safe shape)

For comparison, find `if (<session>->initial_width)` / `if (<session>->is_initialized)` / `if (<session>->created)` / `if (<session>->inited)` style guards that precede the overwrite. Use these as **sanitizers** in the TaintTracking config — flows that pass through them are safe.

## Iteration loop instructions

When CodeQL fails to compile or returns 0 results:

- **0 results, common cause**: the function-name substring is too narrow. Broaden to include legacy spellings — `_set_cfg`, `Reconfigure`, `_update`, etc.
- **0 results, deeper cause**: the codebase doesn't use whole-struct overwrite — it might do per-field copies. In that case, restate the sink: any sequence of `<session>-><field> = <new>-><field>;` assignments where `<field>` is a buffer-sizing field.
- **Compile error on TaintTracking**: missing `import semmle.code.cpp.dataflow.TaintTracking`. Add it and re-run.
- **Compile error on `getValue()`**: range analysis is in a separate module — `import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis`.

## Useful CodeQL libraries

```ql
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.commons.Allocation
```

## Honest caveats

The bug class requires **interprocedural reasoning** across the `_set_config` / `_change_config` / `_alloc` boundary. Pure intraprocedural pattern matching will produce both false positives (any whole-struct copy looks suspicious) and false negatives (the alloc gate is in a different file).

Lean conservative on confidence. Lean toward **needs_review** when the bug requires understanding which fields size which buffers — that's a property of the codec spec, not of the code.

The **negative class**: codecs that support reconfigure correctly will either:
- Keep buffer-sizing fields immutable after init (and reject `_set_config` calls that change them).
- Re-run the full alloc pipeline on every `_set_config` call.

Don't flag those.

## Output

For each candidate:

- `cveAnchor`: "CVE-2023-5217"
- `file`, `function`, `line` (the assignment site)
- `bufferSizingFields`: array of field names used at init to size buffers
- `gateFields`: array of field names used to gate reallocs
- `verdict`: `tp` | `fp` | `needs_review`
- `confidence`: 0..1 (lean conservative)
- `mitigation`: 1-2 sentences on the simplest fix (preserve gate fields when init has already run, mirror the libvpx 3fbd1dc patch).

Cite CVE-2023-5217 in the rationale and link to the libvpx patch shape.
