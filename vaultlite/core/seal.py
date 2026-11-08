"""Vault lifecycle and Seal state machine.  OWNER: Mohammed Siraj.

This module manages the vault's state transitions and in-memory key lifecycle.

State Machine:
    UNINITIALIZED ──(initialize)──> SEALED
         ▲                            │
         │                            ▼ (submit shares < k)
         │                         UNSEALING
         │                            │
         │                            ▼ (submit k-th valid share)
         │                         UNSEALED
         │                            │
         └────────(seal)──────────────┘

Security invariants:
- The master key is ephemeral: it is generated at init, split into Shamir
  shares, used to seal the keyring, and immediately discarded from memory.
- The KEK (Key Encryption Key) lives in memory ONLY while state == UNSEALED.
- Calling seal() immediately clears the KEK and any pending shares from memory.
- Wrong or corrupted shares are caught by verify_key_check() and rejected
  without exposing key material or opening the keyring.
"""
from enum import Enum
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from vaultlite.core.storage import Storage
from vaultlite.crypto import envelope, keyring, rotation, shamir, signing
from vaultlite.crypto.errors import (
    DecryptionError,
    InvalidSharesError,
    WrongMasterKeyError,
)
from vaultlite.crypto.shamir import Share

DEFAULT_SHARES_COUNT = 5
DEFAULT_THRESHOLD = 3


class VaultState(str, Enum):
    """The four operational states of the vault."""
    UNINITIALIZED = "uninitialized"
    SEALED = "sealed"
    UNSEALING = "unsealing"
    UNSEALED = "unsealed"


class SealManager:
    """Coordinates vault initialization, unsealing, sealing, and key state."""

    def __init__(self, storage: Storage) -> None:
        self._storage = storage
        self._state: VaultState = VaultState.UNINITIALIZED
        self._kek: Optional[bytes] = None
        self._signing_priv: Optional[ed25519.Ed25519PrivateKey] = None
        self._shares: dict[int, Share] = {}  # index -> Share (deduplicates shares)
        self._threshold = DEFAULT_THRESHOLD
        self._shares_count = DEFAULT_SHARES_COUNT
        self._sync_state_from_storage()

    def _sync_state_from_storage(self) -> None:
        """Inspect storage to determine whether vault is initialized or sealed."""
        if self._storage.is_initialized():
            self._state = VaultState.SEALED
            raw_k = self._storage.get_meta("threshold")
            if raw_k and len(raw_k) >= 2:
                self._threshold = int.from_bytes(raw_k, "big")
            raw_n = self._storage.get_meta("shares_count")
            if raw_n and len(raw_n) >= 2:
                self._shares_count = int.from_bytes(raw_n, "big")
        else:
            self._state = VaultState.UNINITIALIZED

    @property
    def state(self) -> VaultState:
        """Return the current operational state."""
        return self._state

    @property
    def is_initialized(self) -> bool:
        """True if the vault has been initialized."""
        return self._state != VaultState.UNINITIALIZED

    @property
    def is_unsealed(self) -> bool:
        """True if the vault is unsealed and ready to process secrets."""
        return self._state == VaultState.UNSEALED

    @property
    def threshold(self) -> int:
        """Number of shares required to unseal."""
        return self._threshold

    @property
    def shares_count(self) -> int:
        """Total number of shares generated at initialization."""
        return self._shares_count

    @property
    def shares_collected(self) -> int:
        """Number of unique valid shares submitted in the current unseal attempt."""
        return len(self._shares)

    def status(self) -> dict[str, Any]:
        """Return a dictionary describing the current vault status."""
        needed = 0
        if self._state == VaultState.UNSEALING or self._state == VaultState.SEALED:
            needed = max(0, self._threshold - len(self._shares))

        return {
            "initialized": self.is_initialized,
            "state": self._state.value,
            "threshold": self._threshold,
            "shares_count": self._shares_count,
            "shares_collected": len(self._shares),
            "shares_needed": needed,
        }

    # ------------------------------------------------------------- init
    def initialize(
        self, n: int = DEFAULT_SHARES_COUNT, k: int = DEFAULT_THRESHOLD
    ) -> list[str]:
        """Initialize a fresh vault.

        Generates the master key, splits it into `n` Shamir shares with threshold `k`,
        encrypts the keyring and creates the key-check blob, stores them in SQLite,
        and immediately wipes the master key from memory.

        Returns:
            list[str]: Formatted unseal shares to distribute to custodians.
        """
        if self.is_initialized:
            raise ValueError("vault is already initialized")
        if not (1 < k <= n <= 255):
            raise ValueError("threshold k and shares count n must satisfy 1 < k <= n <= 255")

        # 1. Generate master key
        master = envelope.generate_master_key()

        try:
            # 2. Create keyring and key-check blobs
            keyring_blob, kek = keyring.make_keyring(master)
            check_blob = keyring.make_key_check(master)

            # 3. Create digital signing keypair for audit non-repudiation
            signing_priv, signing_pub = signing.generate_signing_key()
            signing_blob = signing.wrap_signing_key(kek, signing_priv)
            pub_hex = signing.public_key_to_hex(signing_pub)

            # 4. Split master key into Shamir shares
            shares = shamir.split(master, n=n, k=k)

            # 5. Save metadata to storage
            self._storage.save_meta("keyring_blob", keyring_blob)
            self._storage.save_meta("check_blob", check_blob)
            self._storage.save_meta("signing_blob", signing_blob)
            self._storage.save_meta("signing_pub", pub_hex.encode("utf-8"))
            self._storage.save_meta("threshold", k.to_bytes(2, "big"))
            self._storage.save_meta("shares_count", n.to_bytes(2, "big"))

            self._threshold = k
            self._shares_count = n
            self._state = VaultState.SEALED
            self._shares.clear()

            # 5. Return shares formatted as strings for custodians
            return [s.to_str() for s in shares]
        finally:
            # Explicit memory hygiene: delete master key reference
            del master

    # ----------------------------------------------------------- unseal
    def submit_share(self, share_str: str) -> tuple[VaultState, int]:
        """Submit one unseal share.

        Args:
            share_str: Formatted share string (e.g. '1-3a8f...').

        Returns:
            tuple[VaultState, int]: (new_state, remaining_shares_needed)

        Raises:
            ValueError: If the vault is uninitialized or share string is malformed.
            WrongMasterKeyError: If threshold shares were collected but they failed
                                 validation against the key-check blob.
        """
        if self._state == VaultState.UNINITIALIZED:
            raise ValueError("vault is not initialized")
        if self._state == VaultState.UNSEALED:
            return VaultState.UNSEALED, 0

        # Parse share (raises InvalidSharesError on malformed text/out-of-range)
        share = Share.from_str(share_str)

        # Record share (deduplicates by share.index)
        self._shares[share.index] = share

        # Check if threshold is met
        if len(self._shares) < self._threshold:
            self._state = VaultState.UNSEALING
            return VaultState.UNSEALING, self._threshold - len(self._shares)

        # Threshold reached: attempt reconstruction
        shares_to_combine = list(self._shares.values())[: self._threshold]
        try:
            candidate_master = shamir.combine(shares_to_combine)
        except InvalidSharesError as exc:
            # Bad shares that fail polynomial/decoding checks
            self._shares.clear()
            self._state = VaultState.SEALED
            raise WrongMasterKeyError("invalid shares provided") from exc

        check_blob = self._storage.get_meta("check_blob")
        keyring_blob = self._storage.get_meta("keyring_blob")

        if not check_blob or not keyring_blob:
            self._shares.clear()
            self._state = VaultState.SEALED
            raise RuntimeError("corrupted vault storage: missing keyring or check blob")

        # Verify candidate master key against key-check blob
        if not keyring.verify_key_check(candidate_master, check_blob):
            self._shares.clear()
            self._state = VaultState.SEALED
            raise WrongMasterKeyError("shares reconstructed an invalid master key")

        # Open keyring into memory
        self._kek = keyring.open_keyring(candidate_master, keyring_blob)

        # Unwrap private signing key into memory for audit non-repudiation
        signing_blob = self._storage.get_meta("signing_blob")
        if signing_blob:
            self._signing_priv = signing.unwrap_signing_key(self._kek, signing_blob)

        # Wipe ephemeral master key and collected shares
        del candidate_master
        self._shares.clear()

        self._state = VaultState.UNSEALED
        return VaultState.UNSEALED, 0

    def reset_unseal(self) -> None:
        """Clear any partially submitted shares without sealing an open vault."""
        self._shares.clear()
        if self._state == VaultState.UNSEALING:
            self._state = VaultState.SEALED

    # ------------------------------------------------------------- seal
    def seal(self) -> None:
        """Lock the vault immediately, purging KEK and collected shares from memory."""
        self._kek = None
        self._signing_priv = None
        self._shares.clear()
        if self.is_initialized:
            self._state = VaultState.SEALED

    # ------------------------------------------------------- key access
    def get_kek(self) -> bytes:
        """Return the unsealed KEK for secret operations.

        Raises:
            RuntimeError: If called while the vault is not unsealed.
        """
        if self._state != VaultState.UNSEALED or self._kek is None:
            raise RuntimeError("vault is sealed; unseal required before key operations")
        return self._kek

    def get_signing_key(self) -> ed25519.Ed25519PrivateKey:
        """Return the unwrapped Ed25519 private signing key.

        Raises:
            RuntimeError: If called while the vault is not unsealed.
        """
        if self._state != VaultState.UNSEALED or self._signing_priv is None:
            raise RuntimeError("vault is sealed; unseal required before signing operations")
        return self._signing_priv

    def get_signing_public_key(self) -> Optional[ed25519.Ed25519PublicKey]:
        """Return the Ed25519 public verification key (available even while sealed)."""
        raw_hex = self._storage.get_meta("signing_pub")
        if not raw_hex:
            return None
        return signing.public_key_from_hex(raw_hex.decode("utf-8"))

    # --------------------------------------------------------- rotation
    def rotate_master_key(self, custodian_shares: list[str]) -> list[str]:
        """Rotate the master key using a quorum of unseal shares.

        Reconstructs the current master key, generates a fresh master key,
        re-encrypts the keyring under the new master key, updates the key-check
        blob, and returns the new unseal shares.

        The KEK is unchanged, so existing stored secrets remain valid without
        re-encryption.
        """
        if not self.is_initialized:
            raise ValueError("vault is not initialized")
        if len(custodian_shares) < self._threshold:
            raise ValueError(f"at least {self._threshold} shares required for rotation")

        shares_obj = [Share.from_str(s) for s in custodian_shares[: self._threshold]]
        old_master = shamir.combine(shares_obj)

        check_blob = self._storage.get_meta("check_blob")
        if not check_blob or not keyring.verify_key_check(old_master, check_blob):
            raise WrongMasterKeyError("provided shares do not match current master key")

        keyring_blob = self._storage.get_meta("keyring_blob")
        if not keyring_blob:
            raise RuntimeError("keyring blob missing from storage")

        # Execute rotation via Student A's rotation module
        res = rotation.rotate_master_key(
            old_master, keyring_blob, n=self._shares_count, k=self._threshold
        )

        # Store updated blobs
        self._storage.save_meta("keyring_blob", res.keyring_blob)
        self._storage.save_meta("check_blob", res.key_check_blob)

        # If currently unsealed, our in-memory KEK remains unchanged and valid
        del old_master
        return [s.to_str() for s in res.new_shares]

    def rotate_kek(self, custodian_shares: list[str]) -> None:
        """Rotate the KEK (Key Encryption Key).

        Re-encrypts the data encryption key (DEK) of every stored secret
        from the old KEK to the new KEK using envelope.rewrap_dek.
        Plaintext values are never decrypted during this process.
        """
        if not self.is_initialized:
            raise ValueError("vault is not initialized")
        if len(custodian_shares) < self._threshold:
            raise ValueError(f"at least {self._threshold} shares required for rotation")

        shares_obj = [Share.from_str(s) for s in custodian_shares[: self._threshold]]
        master = shamir.combine(shares_obj)

        check_blob = self._storage.get_meta("check_blob")
        if not check_blob or not keyring.verify_key_check(master, check_blob):
            raise WrongMasterKeyError("provided shares do not match current master key")

        keyring_blob = self._storage.get_meta("keyring_blob")
        if not keyring_blob:
            raise RuntimeError("keyring blob missing from storage")

        old_kek = keyring.open_keyring(master, keyring_blob)
        new_keyring_blob, new_kek = keyring.make_keyring(master)

        # Re-wrap each secret's DEK
        for path, version, blob in self._storage.get_all_secret_records():
            new_blob = rotation.rewrap_secret(old_kek, new_kek, path, version, blob)
            self._storage.update_secret_blob(path, version, new_blob)

        # Re-wrap signing key with new KEK
        signing_blob = self._storage.get_meta("signing_blob")
        if signing_blob:
            priv = signing.unwrap_signing_key(old_kek, signing_blob)
            new_signing_blob = signing.wrap_signing_key(new_kek, priv)
            self._storage.save_meta("signing_blob", new_signing_blob)
            if self._state == VaultState.UNSEALED:
                self._signing_priv = priv

        # Save new keyring blob
        self._storage.save_meta("keyring_blob", new_keyring_blob)

        # If vault is unsealed, update in-memory KEK
        if self._state == VaultState.UNSEALED:
            self._kek = new_kek

        del master
        del old_kek
