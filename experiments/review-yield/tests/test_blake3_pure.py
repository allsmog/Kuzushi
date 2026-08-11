"""The stdlib BLAKE3 against published vectors and the official binding.

This implementation exists so model export and digest verification need no
installs. It is only trustworthy if it agrees with the reference, so it is
checked against the published unkeyed vectors always, and against the pip
binding of the same Rust crate Kuzushi links whenever that binding is present.
"""

import random
import unittest

from support import has_module

from kuzushi_review_yield.blake3_pure import blake3_hex

PUBLISHED_VECTORS = {
    b"": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    b"abc": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
}

#: Sizes that straddle every structural boundary: block (64), chunk (1024), and
#: the binary tree's merge points.
BOUNDARY_SIZES = [0, 1, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 4096, 10000]


class Blake3PureTest(unittest.TestCase):
    def test_published_vectors(self):
        for data, expected in PUBLISHED_VECTORS.items():
            with self.subTest(length=len(data)):
                self.assertEqual(blake3_hex(data), expected)

    def test_digest_is_64_lowercase_hex(self):
        digest = blake3_hex(b"kuzushi")
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, digest.lower())
        self.assertTrue(all(character in "0123456789abcdef" for character in digest))

    def test_one_bit_changes_the_digest(self):
        self.assertNotEqual(blake3_hex(b"kuzushi"), blake3_hex(b"kuzushj"))

    def test_is_deterministic(self):
        payload = bytes(range(256)) * 9
        self.assertEqual(blake3_hex(payload), blake3_hex(payload))

    @unittest.skipUnless(has_module("blake3"), "optional blake3 binding not installed")
    def test_matches_official_binding_across_chunk_boundaries(self):
        import blake3

        rng = random.Random(6601)
        for size in BOUNDARY_SIZES:
            with self.subTest(size=size):
                payload = bytes(rng.randrange(256) for _ in range(size))
                self.assertEqual(blake3_hex(payload), blake3.blake3(payload).hexdigest())


if __name__ == "__main__":
    unittest.main()
