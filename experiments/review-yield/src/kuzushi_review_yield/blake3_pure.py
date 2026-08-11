"""Pure-Python BLAKE3 (hash mode only), transcribed from the BLAKE3 reference.

Why this exists: the model-artifact digest contract is BLAKE3, but the whole
experiment must run with zero installs (see README, "dependency policy"). The
optional venv's `blake3` binding is the same Rust crate the Kuzushi workspace
uses; `tests/test_blake3_pure.py` asserts this implementation agrees with it
whenever it is installed, and `fixtures/parity/pinned-digests.json` pins the
bytes that PR 4's Rust tests recompute.

Only unkeyed hashing is implemented. Keyed hashing and `derive_key` are not
used by any Kuzushi domain and are deliberately absent rather than untested.
"""

from __future__ import annotations

OUT_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3

IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)

MASK = 0xFFFFFFFF


def _rotr(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & MASK


def _g(state: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = (state[a] + state[b] + mx) & MASK
    state[d] = _rotr(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotr(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & MASK
    state[d] = _rotr(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotr(state[b] ^ state[c], 7)


def _round(state: list[int], m: list[int]) -> None:
    _g(state, 0, 4, 8, 12, m[0], m[1])
    _g(state, 1, 5, 9, 13, m[2], m[3])
    _g(state, 2, 6, 10, 14, m[4], m[5])
    _g(state, 3, 7, 11, 15, m[6], m[7])
    _g(state, 0, 5, 10, 15, m[8], m[9])
    _g(state, 1, 6, 11, 12, m[10], m[11])
    _g(state, 2, 7, 8, 13, m[12], m[13])
    _g(state, 3, 4, 9, 14, m[14], m[15])


def _compress(
    chaining_value: tuple[int, ...],
    block_words: list[int],
    counter: int,
    block_len: int,
    flags: int,
) -> list[int]:
    state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter & MASK,
        (counter >> 32) & MASK,
        block_len,
        flags,
    ]
    block = list(block_words)
    for index in range(7):
        _round(state, block)
        if index < 6:
            block = [block[position] for position in MSG_PERMUTATION]
    for index in range(8):
        state[index] ^= state[index + 8]
        state[index + 8] ^= chaining_value[index]
    return state


def _words_from_bytes(data: bytes) -> list[int]:
    return [
        int.from_bytes(data[offset : offset + 4], "little")
        for offset in range(0, len(data), 4)
    ]


class _Output:
    """A node whose chaining value or root bytes have not been taken yet."""

    def __init__(
        self,
        input_chaining_value: tuple[int, ...],
        block_words: list[int],
        counter: int,
        block_len: int,
        flags: int,
    ) -> None:
        self.input_chaining_value = input_chaining_value
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self) -> tuple[int, ...]:
        words = _compress(
            self.input_chaining_value,
            self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        )
        return tuple(words[:8])

    def root_bytes(self, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            words = _compress(
                self.input_chaining_value,
                self.block_words,
                counter,
                self.block_len,
                self.flags | ROOT,
            )
            for word in words:
                out += word.to_bytes(4, "little")
            counter += 1
        return bytes(out[:length])


class _ChunkState:
    def __init__(self, key_words: tuple[int, ...], chunk_counter: int, flags: int) -> None:
        self.chaining_value = key_words
        self.chunk_counter = chunk_counter
        self.block = bytearray(BLOCK_LEN)
        self.block_len = 0
        self.blocks_compressed = 0
        self.flags = flags

    def length(self) -> int:
        return BLOCK_LEN * self.blocks_compressed + self.block_len

    def start_flag(self) -> int:
        return CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data: memoryview) -> None:
        while data:
            if self.block_len == BLOCK_LEN:
                self._compress_full_block()
            take = min(BLOCK_LEN - self.block_len, len(data))
            self.block[self.block_len : self.block_len + take] = data[:take]
            self.block_len += take
            data = data[take:]

    def _compress_full_block(self) -> None:
        words = _words_from_bytes(bytes(self.block))
        compressed = _compress(
            self.chaining_value,
            words,
            self.chunk_counter,
            BLOCK_LEN,
            self.flags | self.start_flag(),
        )
        self.chaining_value = tuple(compressed[:8])
        self.blocks_compressed += 1
        self.block = bytearray(BLOCK_LEN)
        self.block_len = 0

    def output(self) -> _Output:
        return _Output(
            self.chaining_value,
            _words_from_bytes(bytes(self.block)),
            self.chunk_counter,
            self.block_len,
            self.flags | self.start_flag() | CHUNK_END,
        )


def _parent_output(
    left: tuple[int, ...],
    right: tuple[int, ...],
    key_words: tuple[int, ...],
    flags: int,
) -> _Output:
    return _Output(key_words, list(left) + list(right), 0, BLOCK_LEN, PARENT | flags)


class Blake3Hasher:
    """Incremental unkeyed BLAKE3."""

    def __init__(self) -> None:
        self._key_words = IV
        self._flags = 0
        self._chunk = _ChunkState(IV, 0, 0)
        self._stack: list[tuple[int, ...]] = []

    def update(self, data: bytes) -> "Blake3Hasher":
        view = memoryview(data)
        while view:
            if self._chunk.length() == CHUNK_LEN:
                self._finish_chunk()
            take = min(CHUNK_LEN - self._chunk.length(), len(view))
            self._chunk.update(view[:take])
            view = view[take:]
        return self

    def _finish_chunk(self) -> None:
        chunk_cv = self._chunk.output().chaining_value()
        total_chunks = self._chunk.chunk_counter + 1
        self._merge(chunk_cv, total_chunks)
        self._chunk = _ChunkState(self._key_words, total_chunks, self._flags)

    def _merge(self, new_cv: tuple[int, ...], total_chunks: int) -> None:
        while total_chunks & 1 == 0:
            new_cv = _parent_output(
                self._stack.pop(), new_cv, self._key_words, self._flags
            ).chaining_value()
            total_chunks >>= 1
        self._stack.append(new_cv)

    def digest(self, length: int = OUT_LEN) -> bytes:
        output = self._chunk.output()
        for parent in reversed(self._stack):
            output = _parent_output(
                parent, output.chaining_value(), self._key_words, self._flags
            )
        return output.root_bytes(length)

    def hexdigest(self, length: int = OUT_LEN) -> str:
        return self.digest(length).hex()


def blake3_hex(data: bytes) -> str:
    """Lowercase 64-hex BLAKE3 of `data`."""
    return Blake3Hasher().update(data).hexdigest()
