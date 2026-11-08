"""Tamper-evident audit log with hash chaining and Ed25519 digital signatures.
OWNER: Mohammed Siraj.

This module provides non-repudiation and integrity verification for all vault
operations (unseal, read, write, rotate, token events).

Security properties:
- Hash chaining: Every entry links to the previous link hash via SHA-256:
      link_hash_n = SHA-256(link_hash_{n-1} + canonical_payload_n)
  The chain starts from GENESIS_HASH ("0" * 64). Altering, inserting, or
  deleting an entry invalidates all subsequent link hashes.
- Non-repudiation: Each link hash is digitally signed with the vault's Ed25519
  private key:
      signature_n = Ed25519_Sign(private_key, link_hash_n, context=b"audit-entry")
  Because verification uses the corresponding public key, no party (including
  clients or third parties) could have forged an entry without the private key.
- Sealed events: Events occurring while the vault is sealed (e.g. initial unseal
  attempts) have their signatures marked as "UNSIGNED_VAULT_SEALED" because the
  signing key is locked at rest inside the encrypted keyring.
"""
import json
import time
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from vaultlite.core.storage import Storage
from vaultlite.crypto.signing import (
    GENESIS_HASH,
    chain_hash,
    public_key_from_hex,
    sign,
    verify,
)

CONTEXT_AUDIT = b"audit-entry"
SIG_UNSIGNED_SEALED = "UNSIGNED_VAULT_SEALED"


def canonical_payload(
    actor: str,
    action: str,
    path: str,
    status: int,
    timestamp: float,
) -> str:
    """Serialize audit event fields to a deterministic canonical JSON string."""
    obj = {
        "action": str(action),
        "actor": str(actor),
        "path": str(path),
        "status": int(status),
        "timestamp": float(timestamp),
    }
    # Deterministic: sorted keys and compact separators
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class AuditLogger:
    """Manages append-only chained audit logging and integrity verification."""

    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    def log_event(
        self,
        actor: str,
        action: str,
        path: str = "",
        status: int = 200,
        signing_key: Optional[ed25519.Ed25519PrivateKey] = None,
        timestamp: Optional[float] = None,
    ) -> int:
        """Record an audit event, update the hash chain, and sign the record.

        Args:
            actor: Identity of the requester or custodian (e.g. 'token:admin', 'custodian:1').
            action: Operation name (e.g. 'unseal', 'secret.read', 'secret.write', 'rotate').
            path: Secret path affected, or empty string if global.
            status: HTTP or operational status code (e.g. 200, 403, 500).
            signing_key: Unwrapped Ed25519 private key, or None if vault is sealed.
            timestamp: Explicit Unix timestamp (default: current time).

        Returns:
            int: The sequence number of the newly created entry.
        """
        now = time.time() if timestamp is None else timestamp
        payload = canonical_payload(actor, action, path, status, now)

        # Retrieve the latest link hash from storage
        entries = self._storage.get_audit_entries()
        last_link = entries[-1]["link_hash"] if entries else GENESIS_HASH

        # Compute next chain link
        new_link = chain_hash(last_link, payload)

        # Sign the link hash if signing key is provided
        if signing_key is not None:
            signature = sign(signing_key, new_link, context=CONTEXT_AUDIT)
        else:
            signature = SIG_UNSIGNED_SEALED

        # Append to persistent storage
        return self._storage.append_audit_entry(
            actor=actor,
            action=action,
            path=path,
            status=status,
            link_hash=new_link,
            signature=signature,
            timestamp=now,
        )

    def verify_chain(
        self, pub_key: Optional[ed25519.Ed25519PublicKey] = None
    ) -> tuple[bool, Optional[str]]:
        """Verify the cryptographic integrity of the entire audit trail.

        Iterates through all entries from sequence 1 to N, recomputing each
        chain hash and verifying every Ed25519 signature.

        Returns:
            tuple[bool, Optional[str]]: (is_valid, error_reason)
        """
        entries = self._storage.get_audit_entries()
        if not entries:
            return True, None

        # If public key wasn't explicitly supplied, check storage
        if pub_key is None:
            pub_hex = self._storage.get_meta("signing_pub")
            if pub_hex:
                pub_key = public_key_from_hex(pub_hex.decode("utf-8"))

        current_link = GENESIS_HASH

        for idx, entry in enumerate(entries):
            seq = entry["seq"]
            # 1. Re-serialize entry payload canonically
            payload = canonical_payload(
                actor=entry["actor"],
                action=entry["action"],
                path=entry["path"],
                status=entry["status"],
                timestamp=entry["timestamp"],
            )

            # 2. Check hash chain link
            expected_link = chain_hash(current_link, payload)
            if expected_link != entry["link_hash"]:
                return (
                    False,
                    f"hash chain mismatch at sequence {seq}: expected {expected_link}, got {entry['link_hash']}",
                )

            # 3. Verify digital signature if entry was signed
            sig = entry["signature"]
            if sig != SIG_UNSIGNED_SEALED:
                if pub_key is None:
                    return (
                        False,
                        f"signed entry at sequence {seq} cannot be verified: missing public key",
                    )
                if not verify(pub_key, entry["link_hash"], sig, context=CONTEXT_AUDIT):
                    return False, f"invalid digital signature at sequence {seq}"

            current_link = entry["link_hash"]

        return True, None
