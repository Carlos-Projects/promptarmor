import hashlib
import secrets

_ALLOWED_HASHES = frozenset({"sha256", "sha384", "sha512"})


def hash_prompt(prompt: str, algorithm: str = "sha256") -> str:
    if algorithm not in _ALLOWED_HASHES:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}. Allowed: {', '.join(sorted(_ALLOWED_HASHES))}")
    h = hashlib.new(algorithm)
    h.update(prompt.encode("utf-8"))
    return h.hexdigest()


def generate_fingerprint() -> str:
    return secrets.token_hex(16)
