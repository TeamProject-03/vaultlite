"""Keyring (KEK storage) and key-check blob.  OWNER: Student A."""


def make_keyring(master_key: bytes) -> tuple[bytes, bytes]:
    """Return (keyring_blob, kek). The KEK is encrypted under master_key."""
    raise NotImplementedError("A: implement make_keyring")


def open_keyring(master_key: bytes, keyring_blob: bytes) -> bytes:
    """Return the KEK. Raises WrongMasterKeyError if master_key is wrong."""
    raise NotImplementedError("A: implement open_keyring")


def make_key_check(master_key: bytes) -> bytes:
    """Encrypt a known constant under master_key."""
    raise NotImplementedError("A: implement make_key_check")


def verify_key_check(master_key: bytes, key_check_blob: bytes) -> bool:
    """True if master_key decrypts the key-check blob."""
    raise NotImplementedError("A: implement verify_key_check")
