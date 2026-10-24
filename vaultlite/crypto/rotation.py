"""Key rotation.  OWNER: Student A."""
from dataclasses import dataclass

from vaultlite.crypto.shamir import Share


@dataclass
class MasterRotationResult:
    keyring_blob: bytes
    key_check_blob: bytes
    new_shares: list[Share]


def rotate_master_key(old_master_key: bytes, keyring_blob: bytes,
                      n: int = 5, k: int = 3) -> MasterRotationResult:
    """New master key, re-encrypted keyring, and fresh shares."""
    raise NotImplementedError("A: implement rotate_master_key")


def rewrap_secret(old_kek: bytes, new_kek: bytes, path: str, version: int,
                  blob: bytes) -> bytes:
    """Re-wrap one secret's DEK from old_kek to new_kek."""
    raise NotImplementedError("A: implement rewrap_secret")
