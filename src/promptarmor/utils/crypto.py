import hashlib
import secrets


def hash_prompt(prompt: str, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    h.update(prompt.encode("utf-8"))
    return h.hexdigest()


def generate_fingerprint() -> str:
    return secrets.token_hex(16)
