"""Digital signatures and hash chaining for non-repudiation.  OWNER: Mohammed Siraj.

This module provides Ed25519 digital signatures and append-only hash chaining
for tamper-evident audit logging.

Security invariants:
- Signatures provide non-repudiation: only the holder of the private key
  could produce the signature. Unlike HMAC, signatures cannot be forged even
  by someone who can verify them.
- Purpose separation: Signatures bind a context domain (e.g. b'audit-entry')
  so a signature valid in one context cannot be replayed in another.
- Append-only hash chain: Each audit link is SHA-256(previous_link + payload).
  Editing or deleting any entry breaks all subsequent hashes in the chain.
- The private signing key is encrypted under the KEK at rest and exists in
  memory only while the vault is unsealed.
"""
import hashlib
import secrets
from typing import Union

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vaultlite.crypto.errors import DecryptionError

KEY_SIZE = 32
NONCE_SIZE = 12
FORMAT_V1 = b"\x01"
SIGNING_KEY_INFO = b"vaultlite/signing-key/v1"
GENESIS_HASH = "0" * 64


def generate_signing_key() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate an Ed25519 keypair for audit logging and non-repudiation."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def public_key_to_hex(pub_key: ed25519.Ed25519PublicKey) -> str:
    """Serialize an Ed25519 public key to a 64-character hexadecimal string."""
    raw = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def public_key_from_hex(hex_str: str) -> ed25519.Ed25519PublicKey:
    """Deserialize an Ed25519 public key from a 64-character hex string."""
    try:
        raw = bytes.fromhex(hex_str.strip())
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise ValueError("invalid public key hex string") from exc


def wrap_signing_key(kek: bytes, priv_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Encrypt the private signing key under the KEK using AES-256-GCM."""
    if not isinstance(kek, bytes) or len(kek) != KEY_SIZE:
        raise ValueError("kek must be 32 bytes")

    raw_priv = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = AESGCM(kek).encrypt(nonce, raw_priv, SIGNING_KEY_INFO)
    return FORMAT_V1 + nonce + ct


def unwrap_signing_key(kek: bytes, blob: bytes) -> ed25519.Ed25519PrivateKey:
    """Decrypt the private signing key using the KEK."""
    if not isinstance(kek, bytes) or len(kek) != KEY_SIZE:
        raise ValueError("kek must be 32 bytes")
    if len(blob) < 1 + NONCE_SIZE + KEY_SIZE or blob[:1] != FORMAT_V1:
        raise DecryptionError("invalid signing key blob")

    nonce = blob[1:1 + NONCE_SIZE]
    ciphertext = blob[1 + NONCE_SIZE:]
    try:
        raw_priv = AESGCM(kek).decrypt(nonce, ciphertext, SIGNING_KEY_INFO)
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv)
    except (InvalidTag, ValueError) as exc:
        raise DecryptionError("cannot unwrap signing key") from exc


def chain_hash(previous_hash: Union[str, bytes], payload: Union[str, bytes]) -> str:
    """Compute the SHA-256 hash link connecting `previous_hash` and `payload`."""
    prev_bytes = previous_hash.encode("utf-8") if isinstance(previous_hash, str) else previous_hash
    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload

    h = hashlib.sha256()
    h.update(prev_bytes)
    h.update(payload_bytes)
    return h.hexdigest()


def sign(
    priv_key: ed25519.Ed25519PrivateKey,
    message: Union[str, bytes],
    context: bytes = b"audit-entry",
) -> str:
    """Sign `message` bound to `context`. Returns hex-encoded signature."""
    msg_bytes = message.encode("utf-8") if isinstance(message, str) else message
    data_to_sign = context + b":" + msg_bytes
    sig = priv_key.sign(data_to_sign)
    return sig.hex()


def verify(
    pub_key: ed25519.Ed25519PublicKey,
    message: Union[str, bytes],
    signature: Union[str, bytes],
    context: bytes = b"audit-entry",
) -> bool:
    """Verify an Ed25519 signature.

    Returns False on any failure (tampering, wrong key, malformed input).
    Never raises.
    """
    try:
        if isinstance(signature, str):
            sig_bytes = bytes.fromhex(signature.strip())
        else:
            sig_bytes = signature

        msg_bytes = message.encode("utf-8") if isinstance(message, str) else message
        data_to_verify = context + b":" + msg_bytes
        pub_key.verify(sig_bytes, data_to_verify)
        return True
    except Exception:
        return False
