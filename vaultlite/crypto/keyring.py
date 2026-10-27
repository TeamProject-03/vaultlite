"""Keyring (KEK storage) and key-check blob.  OWNER: Student A.

The master key is never stored. Two things are stored on disk instead:

  keyring blob   the KEK, encrypted under a key derived from the master key
  key-check blob a known constant, encrypted under a different derived key

At unseal time the server rebuilds a candidate master key from the Shamir
shares, then verify_key_check() tells it whether that key is correct before
the keyring is opened. Without this, wrong shares would silently produce a
garbage key.

Each purpose gets its own subkey via HKDF-SHA256 (domain separation), so a
blob made for one purpose can never be accepted for the other.
"""
import hmac
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vaultlite.crypto.errors import WrongMasterKeyError

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
FORMAT_V1 = b"\x01"

_KEYRING_INFO = b"vaultlite/v1/keyring"
_CHECK_INFO = b"vaultlite/v1/key-check"
_CHECK_CONSTANT = b"vaultlite key check constant v1"


def _derive(master_key: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE,
                salt=None, info=info).derive(master_key)


def _seal(master_key: bytes, info: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = AESGCM(_derive(master_key, info)).encrypt(nonce, plaintext, info)
    return FORMAT_V1 + nonce + ct


def _open(master_key: bytes, info: bytes, blob: bytes) -> bytes:
    """Return the plaintext, or raise InvalidTag / ValueError."""
    if len(blob) < 1 + NONCE_SIZE + TAG_SIZE or blob[:1] != FORMAT_V1:
        raise ValueError("invalid blob")
    nonce = blob[1:1 + NONCE_SIZE]
    return AESGCM(_derive(master_key, info)).decrypt(
        nonce, blob[1 + NONCE_SIZE:], info)


def _check_master(master_key: bytes) -> None:
    if not isinstance(master_key, bytes) or len(master_key) != KEY_SIZE:
        raise ValueError("master key must be 32 bytes")


def make_keyring(master_key: bytes) -> tuple[bytes, bytes]:
    """Create a new random KEK and encrypt it under `master_key`.

    Returns (keyring_blob, kek). Store keyring_blob on disk; keep kek in
    memory only. Used at init time.
    """
    _check_master(master_key)
    kek = secrets.token_bytes(KEY_SIZE)
    return _seal(master_key, _KEYRING_INFO, kek), kek


def open_keyring(master_key: bytes, keyring_blob: bytes) -> bytes:
    """Decrypt the keyring and return the KEK. Used at unseal time.

    Raises WrongMasterKeyError if the master key is wrong or the blob was
    tampered with (the two cases are indistinguishable by design).
    """
    _check_master(master_key)
    try:
        return _open(master_key, _KEYRING_INFO, keyring_blob)
    except (InvalidTag, ValueError) as exc:
        raise WrongMasterKeyError("cannot open keyring") from exc


def make_key_check(master_key: bytes) -> bytes:
    """Encrypt a known constant under a key derived from `master_key`."""
    _check_master(master_key)
    return _seal(master_key, _CHECK_INFO, _CHECK_CONSTANT)


def verify_key_check(master_key: bytes, key_check_blob: bytes) -> bool:
    """True only if `master_key` correctly decrypts the key-check blob.

    Never raises for a bad key: garbage from wrong shares simply gives False.
    """
    if not isinstance(master_key, bytes) or len(master_key) != KEY_SIZE:
        return False
    try:
        plain = _open(master_key, _CHECK_INFO, key_check_blob)
    except (InvalidTag, ValueError):
        return False
    return hmac.compare_digest(plain, _CHECK_CONSTANT)

def seal_keyring(master_key: bytes, kek: bytes) -> bytes:
    """Encrypt an existing `kek` under `master_key`.

    Used by master-key rotation: the KEK stays the same, only the key that
    protects it changes.
    """
    _check_master(master_key)
    if not isinstance(kek, bytes) or len(kek) != KEY_SIZE:
        raise ValueError("kek must be 32 bytes")
    return _seal(master_key, _KEYRING_INFO, kek)