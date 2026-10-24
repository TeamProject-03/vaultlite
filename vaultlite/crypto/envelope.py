"""Envelope encryption with AES-256-GCM.  OWNER: Student A."""


def generate_master_key() -> bytes:
    """Return 32 random bytes from a CSPRNG."""
    raise NotImplementedError("A: implement generate_master_key")


def encrypt_secret(kek: bytes, path: str, version: int, plaintext: bytes) -> bytes:
    """Fresh DEK and nonce per call; AAD = path:version; DEK wrapped under kek."""
    raise NotImplementedError("A: implement encrypt_secret")


def decrypt_secret(kek: bytes, path: str, version: int, blob: bytes) -> bytes:
    """Reverse of encrypt_secret. Raises DecryptionError on tampering."""
    raise NotImplementedError("A: implement decrypt_secret")
