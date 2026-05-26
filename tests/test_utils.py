from promptarmor.utils.crypto import generate_fingerprint, hash_prompt


class TestCrypto:
    def test_hash_prompt_sha256(self):
        h = hash_prompt("hello world")
        assert len(h) == 64
        assert h == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_hash_prompt_different_inputs(self):
        h1 = hash_prompt("hello")
        h2 = hash_prompt("world")
        assert h1 != h2

    def test_hash_prompt_empty(self):
        h = hash_prompt("")
        assert len(h) == 64

    def test_hash_prompt_unicode(self):
        h = hash_prompt("héllo wörld 🚀")
        assert isinstance(h, str)
        assert len(h) == 64

    def test_hash_prompt_custom_algorithm(self):
        h = hash_prompt("test", algorithm="sha512")
        assert len(h) == 128

    def test_hash_prompt_consistency(self):
        h1 = hash_prompt("consistent message")
        h2 = hash_prompt("consistent message")
        assert h1 == h2

    def test_generate_fingerprint_length(self):
        fp = generate_fingerprint()
        assert len(fp) == 32

    def test_generate_fingerprint_hex(self):
        fp = generate_fingerprint()
        int(fp, 16)

    def test_generate_fingerprint_uniqueness(self):
        fps = {generate_fingerprint() for _ in range(100)}
        assert len(fps) == 100

    def test_generate_fingerprint_type(self):
        fp = generate_fingerprint()
        assert isinstance(fp, str)
