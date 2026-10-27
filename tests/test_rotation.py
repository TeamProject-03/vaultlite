import pytest

from vaultlite.crypto.envelope import (
    decrypt_secret, encrypt_secret, generate_master_key)
from vaultlite.crypto.errors import DecryptionError, WrongMasterKeyError
from vaultlite.crypto.keyring import (
    make_key_check, make_keyring, open_keyring, verify_key_check)
from vaultlite.crypto.rotation import rewrap_secret, rotate_master_key
from vaultlite.crypto.shamir import combine, split


def _setup():
    master = generate_master_key()
    keyring_blob, kek = make_keyring(master)
    return master, keyring_blob, kek


def test_master_rotation_keeps_the_kek():
    master, keyring_blob, kek = _setup()
    result = rotate_master_key(master, keyring_blob)
    new_master = combine(result.new_shares[:3])
    assert open_keyring(new_master, result.keyring_blob) == kek


def test_secrets_stay_readable_after_master_rotation():
    master, keyring_blob, kek = _setup()
    blob = encrypt_secret(kek, "db/password", 1, b"hunter2")
    result = rotate_master_key(master, keyring_blob)
    new_master = combine([result.new_shares[4], result.new_shares[0],
                          result.new_shares[2]])
    new_kek = open_keyring(new_master, result.keyring_blob)
    assert decrypt_secret(new_kek, "db/password", 1, blob) == b"hunter2"


def test_new_shares_verify_against_new_key_check():
    master, keyring_blob, _ = _setup()
    result = rotate_master_key(master, keyring_blob, n=5, k=3)
    assert len(result.new_shares) == 5
    new_master = combine(result.new_shares[:3])
    assert verify_key_check(new_master, result.key_check_blob) is True


def test_old_master_and_old_shares_stop_working():
    master, keyring_blob, _ = _setup()
    old_check = make_key_check(master)
    old_shares = split(master, 5, 3)
    result = rotate_master_key(master, keyring_blob)
    with pytest.raises(WrongMasterKeyError):
        open_keyring(master, result.keyring_blob)
    assert verify_key_check(master, result.key_check_blob) is False
    rebuilt_old = combine(old_shares[:3])
    assert verify_key_check(rebuilt_old, result.key_check_blob) is False
    assert verify_key_check(rebuilt_old, old_check) is True  # sanity


def test_each_rotation_gives_a_different_master_key():
    master, keyring_blob, _ = _setup()
    r1 = rotate_master_key(master, keyring_blob)
    r2 = rotate_master_key(master, keyring_blob)
    assert combine(r1.new_shares[:3]) != combine(r2.new_shares[:3])


def test_rotation_with_wrong_old_master_rejected():
    _, keyring_blob, _ = _setup()
    with pytest.raises(WrongMasterKeyError):
        rotate_master_key(generate_master_key(), keyring_blob)


def test_rotation_with_bad_threshold_rejected():
    master, keyring_blob, _ = _setup()
    with pytest.raises(ValueError):
        rotate_master_key(master, keyring_blob, n=2, k=3)


def test_rewrap_moves_secret_to_new_kek():
    _, _, old_kek = _setup()
    new_kek = generate_master_key()
    blob = encrypt_secret(old_kek, "api/key", 3, b"token-123")
    new_blob = rewrap_secret(old_kek, new_kek, "api/key", 3, blob)
    assert decrypt_secret(new_kek, "api/key", 3, new_blob) == b"token-123"
    with pytest.raises(DecryptionError):
        decrypt_secret(old_kek, "api/key", 3, new_blob)


def test_rewrap_does_not_touch_the_encrypted_value():
    old_kek, new_kek = generate_master_key(), generate_master_key()
    blob = encrypt_secret(old_kek, "p", 1, b"value")
    new_blob = rewrap_secret(old_kek, new_kek, "p", 1, blob)
    assert new_blob[61:] == blob[61:]      # value nonce + ciphertext unchanged
    assert new_blob[:61] != blob[:61]      # wrapped DEK changed


def test_rewrap_failures():
    old_kek, new_kek = generate_master_key(), generate_master_key()
    blob = encrypt_secret(old_kek, "p", 1, b"value")
    with pytest.raises(DecryptionError):
        rewrap_secret(generate_master_key(), new_kek, "p", 1, blob)
    with pytest.raises(DecryptionError):
        rewrap_secret(old_kek, new_kek, "other", 1, blob)
    with pytest.raises(DecryptionError):
        rewrap_secret(old_kek, new_kek, "p", 2, blob)
    for bad in (b"", b"\x01", blob[:30]):
        with pytest.raises(DecryptionError):
            rewrap_secret(old_kek, new_kek, "p", 1, bad)
    tampered = bytearray(blob)
    tampered[20] ^= 0x01                   # inside the wrapped DEK
    with pytest.raises(DecryptionError):
        rewrap_secret(old_kek, new_kek, "p", 1, bytes(tampered))


def test_full_kek_rotation_flow():
    master, keyring_blob, old_kek = _setup()
    secrets_in_db = {("a/one", 1): b"one", ("b/two", 2): b"two"}
    stored = {key: encrypt_secret(old_kek, key[0], key[1], value)
              for key, value in secrets_in_db.items()}
    new_keyring_blob, new_kek = make_keyring(master)
    stored = {key: rewrap_secret(old_kek, new_kek, key[0], key[1], blob)
              for key, blob in stored.items()}
    assert open_keyring(master, new_keyring_blob) == new_kek
    for key, value in secrets_in_db.items():
        assert decrypt_secret(new_kek, key[0], key[1], stored[key]) == value