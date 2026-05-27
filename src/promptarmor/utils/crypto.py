import hashlib
import secrets

_ALLOWED_HASHES = frozenset({"sha256", "sha384", "sha512"})


def hash_prompt(prompt: str, algorithm: str = "sha256") -> str:
    """Hash a prompt string using the specified algorithm.

    Args:
        prompt: The text to hash.
        algorithm: Hash algorithm (sha256, sha384, sha512).

    Returns:
        Hexadecimal digest string.

    Raises:
        ValueError: If the algorithm is not in the allowed set.
    """
    if algorithm not in _ALLOWED_HASHES:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}. Allowed: {', '.join(sorted(_ALLOWED_HASHES))}")
    h = hashlib.new(algorithm)
    h.update(prompt.encode("utf-8"))
    return h.hexdigest()


def generate_fingerprint() -> str:
    """Generate a cryptographically secure random hex fingerprint (32 chars)."""
    return secrets.token_hex(16)
