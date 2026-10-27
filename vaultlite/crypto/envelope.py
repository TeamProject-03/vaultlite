"""Envelope encryption with AES-256-GCM.  OWNER: Student A.

Each secret gets its own random data key (DEK). The DEK encrypts the value,
and the KEK wraps (encrypts) the DEK. The returned blob holds everything
needed to decrypt except the KEK, so the database stores only this blob.

Blob layout (all fixed-size except the last field):
    1 byte   format version (0x01)
    12 bytes nonce used to wrap the DEK
    48 bytes wrapped DEK (32-byte key + 16-byte GCM tag)
    12 bytes nonce used to encrypt the value
    n bytes  ciphertext + 16-byte GCM tag

Both GCM operations use the secret's path and version as AAD, so a blob
cannot be moved to another path or replayed as another version.
"""
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vaultlite.crypto.errors import DecryptionError

KEY_SIZE = 32          # AES-256
NONCE_SIZE = 12        # 96-bit nonce, the size GCM is designed for
TAG_SIZE = 16
FORMAT_V1 = b"\x01"
_WRAPPED_DEK_SIZE = KEY_SIZE + TAG_SIZE
_HEADER_SIZE = 1 + NONCE_SIZE + _WRAPPED_DEK_SIZE + NONCE_SIZE


def generate_master_key() -> bytes:
    """Return 32 random bytes from the OS CSPRNG."""
    return secrets.token_bytes(KEY_SIZE)


def _aad(path: str, version: int) -> bytes:
    # Length-prefixed so different (path, version) pairs can never produce
    # the same bytes, whatever characters the path contains.
    p = path.encode("utf-8")
    return len(p).to_bytes(4, "big") + p + version.to_bytes(8, "big")


def _check_inputs(kek: bytes, path: str, version: int) -> None:
    if not isinstance(kek, bytes) or len(kek) != KEY_SIZE:
        raise ValueError("kek must be 32 bytes")
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        raise ValueError("version must be a non-negative integer")


def encrypt_secret(kek: bytes, path: str, version: int, plaintext: bytes) -> bytes:
    """Encrypt `plaintext` for the secret at `path`/`version`.

    A fresh random DEK and fresh random nonces are generated on every call,
    so encrypting the same value twice gives different blobs.
    """
    _check_inputs(kek, path, version)
    aad = _aad(path, version)
    dek = secrets.token_bytes(KEY_SIZE)
    wrap_nonce = secrets.token_bytes(NONCE_SIZE)
    wrapped_dek = AESGCM(kek).encrypt(wrap_nonce, dek, aad)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return FORMAT_V1 + wrap_nonce + wrapped_dek + nonce + ciphertext


def decrypt_secret(kek: bytes, path: str, version: int, blob: bytes) -> bytes:
    """Reverse encrypt_secret().

    Raises DecryptionError on any tampering, wrong key, or wrong
    path/version. The error is deliberately generic.
    """
    _check_inputs(kek, path, version)
    if len(blob) < _HEADER_SIZE + TAG_SIZE or blob[:1] != FORMAT_V1:
        raise DecryptionError("invalid blob")
    aad = _aad(path, version)
    pos = 1
    wrap_nonce = blob[pos:pos + NONCE_SIZE]
    pos += NONCE_SIZE
    wrapped_dek = blob[pos:pos + _WRAPPED_DEK_SIZE]
    pos += _WRAPPED_DEK_SIZE
    nonce = blob[pos:pos + NONCE_SIZE]
    ciphertext = blob[pos + NONCE_SIZE:]
    try:
        dek = AESGCM(kek).decrypt(wrap_nonce, wrapped_dek, aad)
        return AESGCM(dek).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("decryption failed") from exc

    def rewrap_dek(old_kek: bytes, new_kek: bytes, path: str, version: int,
               blob: bytes) -> bytes:
    """Move a secret's DEK from `old_kek` to `new_kek` (used for KEK rotation).

    Only the wrapped DEK changes. The encrypted value is copied as it is, so
    the plaintext is never exposed. The value is not re-checked here: any
    tampering with it is still caught later by decrypt_secret().
    """
    _check_inputs(old_kek, path, version)
    _check_inputs(new_kek, path, version)
    if len(blob) < _HEADER_SIZE + TAG_SIZE or blob[:1] != FORMAT_V1:
        raise DecryptionError("invalid blob")
    aad = _aad(path, version)
    old_wrap_nonce = blob[1:1 + NONCE_SIZE]
    wrapped_dek = blob[1 + NONCE_SIZE:1 + NONCE_SIZE + _WRAPPED_DEK_SIZE]
    rest = blob[1 + NONCE_SIZE + _WRAPPED_DEK_SIZE:]   # value nonce + ciphertext
    try:
        dek = AESGCM(old_kek).decrypt(old_wrap_nonce, wrapped_dek, aad)
    except InvalidTag as exc:
        raise DecryptionError("rewrap failed") from exc
    new_wrap_nonce = secrets.token_bytes(NONCE_SIZE)
    new_wrapped_dek = AESGCM(new_kek).encrypt(new_wrap_nonce, dek, aad)
    return FORMAT_V1 + new_wrap_nonce + new_wrapped_dek + rest