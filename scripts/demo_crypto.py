"""Live demo of the VaultLite crypto core.  Run from the project root:

    python scripts/demo_crypto.py          # runs straight through
    python scripts/demo_crypto.py --step   # waits for Enter between steps
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vaultlite.crypto.envelope import (  # noqa: E402
    decrypt_secret, encrypt_secret, generate_master_key)
from vaultlite.crypto.errors import (  # noqa: E402
    DecryptionError, InvalidSharesError, WrongMasterKeyError)
from vaultlite.crypto.keyring import (  # noqa: E402
    make_key_check, make_keyring, open_keyring, verify_key_check)
from vaultlite.crypto.rotation import (  # noqa: E402
    rewrap_secret, rotate_master_key)
from vaultlite.crypto.shamir import combine, split  # noqa: E402

STEP = "--step" in sys.argv


def section(title: str) -> None:
    if STEP:
        input("\n[press Enter] ")
    print(f"\n=== {title} ===")


def short(data: bytes) -> str:
    return data.hex()[:32] + "..."


def try_unseal(shares, check_blob, keyring_blob):
    """What the server does: combine shares, verify, then open the keyring."""
    try:
        master = combine(shares)
    except InvalidSharesError:
        return None
    if not verify_key_check(master, check_blob):
        return None
    return open_keyring(master, keyring_blob)


# ---------------------------------------------------------------- 1. init
section("1. INIT: master key, keyring, key-check, 5 shares (3 needed)")
master = generate_master_key()
keyring_blob, kek = make_keyring(master)
check_blob = make_key_check(master)
shares = split(master, n=5, k=3)
del master  # the master key is never stored
for share in shares:
    print(f"  share {share.index}: {share.to_str()[:18]}...")
print("  master key discarded; only the keyring and key-check blob are stored")

# ---------------------------------------------------------------- 2. store
section("2. STORE a secret (envelope encryption, AES-256-GCM)")
stored = encrypt_secret(kek, "db/password", 1, b"S3cr3t-DB-Passw0rd!")
print(f"  stored blob : {short(stored)}  ({len(stored)} bytes)")
print("  plaintext visible in blob?", b"S3cr3t" in stored)

# ---------------------------------------------------------------- 3. unseal
section("3. UNSEAL: 2 shares fail, 3 shares succeed")
two = try_unseal(shares[:2], check_blob, keyring_blob)
print("  2 shares ->", "UNSEALED" if two else "still SEALED")
three = try_unseal([shares[4], shares[0], shares[2]], check_blob, keyring_blob)
print("  3 shares ->", "UNSEALED" if three else "still SEALED")
print("  secret reads back:",
      decrypt_secret(three, "db/password", 1, stored).decode())

# ---------------------------------------------------------------- 4. wrong
section("4. WRONG SHARES from another vault are detected")
other = split(generate_master_key(), 5, 3)
bad = try_unseal([shares[0], shares[1], other[2]], check_blob, keyring_blob)
print("  mixed shares ->", "UNSEALED (BAD!)" if bad else "rejected, still SEALED")

# ---------------------------------------------------------------- 5. tamper
section("5. TAMPERING is detected")
corrupted = bytearray(stored)
corrupted[-1] ^= 0x01
try:
    decrypt_secret(kek, "db/password", 1, bytes(corrupted))
    print("  flipped 1 bit -> accepted (BAD!)")
except DecryptionError:
    print("  flipped 1 bit in the stored blob -> DecryptionError")
try:
    decrypt_secret(kek, "api/key", 1, stored)
    print("  moved to another path -> accepted (BAD!)")
except DecryptionError:
    print("  blob moved to another path -> DecryptionError (AAD binding)")

# ---------------------------------------------------------------- 6. rotate
section("6. ROTATE the master key: new shares, old shares die")
result = rotate_master_key(combine(shares[:3]), keyring_blob)
new_kek = try_unseal(result.new_shares[:3], result.key_check_blob,
                     result.keyring_blob)
print("  new shares ->", "UNSEALED" if new_kek else "SEALED (BAD!)")
old = try_unseal(shares[:3], result.key_check_blob, result.keyring_blob)
print("  old shares ->", "UNSEALED (BAD!)" if old else "rejected")
print("  secret still readable:",
      decrypt_secret(new_kek, "db/password", 1, stored).decode())

# ---------------------------------------------------------------- 7. KEK
section("7. ROTATE the KEK: re-wrap the secret's data key")
keyring_blob2, kek2 = make_keyring(combine(result.new_shares[:3]))
rewrapped = rewrap_secret(new_kek, kek2, "db/password", 1, stored)
print("  new KEK reads it:",
      decrypt_secret(kek2, "db/password", 1, rewrapped).decode())
try:
    decrypt_secret(new_kek, "db/password", 1, rewrapped)
except DecryptionError:
    print("  old KEK  -> DecryptionError")
print("\nDone.")