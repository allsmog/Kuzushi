"""Canonical JSON and the length-framed BLAKE3 framing Kuzushi hashes with.

This module is the Python side of a cross-language contract. The Rust side is
`crates/kuzushi-core/src/identity/hash.rs` (`hash_parts`) and
`crates/kuzushi-core/src/review_yield/domain/canonical_json.rs`. Any change
here is a change to bytes PR 4's Rust tests recompute; see
`fixtures/parity/README.md`.

Framing (mirrors `hash_parts(domain, parts)` exactly):

    blake3( u64_be(10) || b"kuzushi:v3"
         || u64_be(len(domain))   || domain
         || u64_be(len(part_i))   || part_i   for each part )

Canonical JSON: UTF-8, object keys sorted by byte value at every depth, compact
separators, no trailing newline. Kuzushi artifacts are ASCII-only, which is
asserted here, so `ensure_ascii` cannot change the bytes.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Sequence

from .blake3_pure import Blake3Hasher

DOMAIN_PREFIX = b"kuzushi:v3"

#: Floats are quantized to this many fractional digits before serialization so
#: that Python `repr` and Rust `ryu` cannot disagree on the shortest form.
FLOAT_DECIMALS = 6

#: Below this magnitude Python renders exponent notation (`1e-05`), which Rust
#: renders as `1e-5`. Nonzero values under the threshold are snapped to 0.0 so
#: the canonical form stays exponent-free on both sides.
MIN_NONZERO_MAGNITUDE = 1e-4

_NUMBER_WITH_EXPONENT = re.compile(rb"[0-9][eE][+-]?[0-9]")


class CanonicalizationError(ValueError):
    """The value cannot be represented in the cross-language canonical form."""


def quantize_floats(value: Any) -> Any:
    """Recursively round floats to `FLOAT_DECIMALS`, snapping tiny ones to 0.0.

    Booleans are left alone (they are not numbers in JSON) and integers keep
    their integer form, so counts never gain a `.0`.
    """
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        return _quantize_one(value)
    if isinstance(value, dict):
        return {key: quantize_floats(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [quantize_floats(item) for item in value]
    raise CanonicalizationError(f"unsupported JSON value type: {type(value).__name__}")


def _quantize_one(value: float) -> float:
    if value != value or value in (float("inf"), float("-inf")):
        raise CanonicalizationError(f"non-finite float in artifact: {value!r}")
    rounded = round(value, FLOAT_DECIMALS)
    if rounded != 0.0 and abs(rounded) < MIN_NONZERO_MAGNITUDE:
        return 0.0
    return rounded


def canonical_json_bytes(value: Any) -> bytes:
    """Canonical bytes for `value`. Floats must already be quantized."""
    _assert_numbers_are_plain(value)
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    _assert_ascii(encoded)
    return encoded


def canonical_json_bytes_without_key(value: dict[str, Any], key: str) -> bytes:
    """Canonical bytes with one top-level key removed (the hashed form)."""
    return canonical_json_bytes({k: v for k, v in value.items() if k != key})


def _assert_ascii(encoded: bytes) -> None:
    if not encoded.isascii():
        raise CanonicalizationError(
            "artifact contains non-ASCII text; the canonical form is ASCII-only "
            "so Rust and Python cannot diverge on escaping"
        )


def _assert_numbers_are_plain(value: Any) -> None:
    """Rejects any float that would serialize in exponent notation.

    Python writes `1e-05` where Rust's `ryu` writes `1e-5`, so an exponent in the
    canonical bytes would silently break Python/Rust digest parity. Structural
    walk, not a regex over the encoded text: hex digests contain `e` too.
    """
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, float):
        if _NUMBER_WITH_EXPONENT.search(repr(value).encode("ascii")):
            raise CanonicalizationError(
                f"{value!r} serializes in exponent notation; run quantize_floats first"
            )
        return
    if isinstance(value, dict):
        for item in value.values():
            _assert_numbers_are_plain(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _assert_numbers_are_plain(item)


def hash_parts(domain: str, parts: Sequence[bytes]) -> str:
    """Lowercase 64-hex BLAKE3 over the length-framed domain and parts."""
    hasher = Blake3Hasher()
    _update_part(hasher, DOMAIN_PREFIX)
    _update_part(hasher, domain.encode("utf-8"))
    for part in parts:
        _update_part(hasher, part)
    return hasher.hexdigest()


def _update_part(hasher: Blake3Hasher, data: bytes) -> None:
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)


def prefixed_digest(domain: str, parts: Iterable[bytes]) -> str:
    """`blake3:<hex>`, the form every Kuzushi review-yield identifier takes."""
    return f"blake3:{hash_parts(domain, list(parts))}"
