"""Key rotation.  OWNER: Student A.

Two kinds of rotation:

  Master key rotation  rotate_master_key()
      New master key, new Shamir shares, keyring re-encrypted. The KEK is
      unchanged, so no secret needs touching. Old shares stop working.

  KEK rotation  make_keyring(master) for a new KEK, then rewrap_secret()
      for every stored secret. Only the small wrapped DEK of each secret
      changes, the encrypted values are not re-encrypted.
"""
from dataclasses import dataclass

from vaultlite.crypto import envelope, keyring, shamir
from vaultlite.crypto.shamir import Share


@dataclass
class MasterRotationResult:
    keyring_blob: bytes        # keyring re-encrypted under the NEW master key
    key_check_blob: bytes      # new key-check blob
    new_shares: list[Share]    # fresh shares; old shares no longer work


def rotate_master_key(old_master_key: bytes, keyring_blob: bytes,
                      n: int = 5, k: int = 3) -> MasterRotationResult:
    """Generate a new master key, re-encrypt the keyring under it, and issue
    new shares. The new master key itself is discarded, only the shares
    can rebuild it.

    Raises WrongMasterKeyError if `old_master_key` does not open the keyring,
    and ValueError for invalid n/k.
    """
    kek = keyring.open_keyring(old_master_key, keyring_blob)
    new_master = envelope.generate_master_key()
    new_shares = shamir.split(new_master, n, k)      # validates n and k
    return MasterRotationResult(
        keyring_blob=keyring.seal_keyring(new_master, kek),
        key_check_blob=keyring.make_key_check(new_master),
        new_shares=new_shares,
    )


def rewrap_secret(old_kek: bytes, new_kek: bytes, path: str, version: int,
                  blob: bytes) -> bytes:
    """Re-wrap one secret's DEK from old_kek to new_kek without
    re-encrypting the value."""
    return envelope.rewrap_dek(old_kek, new_kek, path, version, blob)