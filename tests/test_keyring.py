import pytest

from vaultlite.crypto.envelope import (
    decrypt_secret, encrypt_secret, generate_master_key)
from vaultlite.crypto.errors import InvalidSharesError, WrongMasterKeyError
from vaultlite.crypto.keyring import (
    make_key_check, make_keyring, open_keyring, verify_key_check)
from vaultlite.crypto.shamir import combine, split


def test_keyring_roundtrip():
    master = generate_master_key()
    blob, kek = make_keyring(master)
    assert len(kek) == 32
    assert open_keyring(master, blob) == kek


def test_each_keyring_has_a_new_random_kek():
    master = generate_master_key()
    _, kek1 = make_keyring(master)
    _, kek2 = make_keyring(master)
    assert kek1 != kek2


def test_kek_not_visible_in_keyring_blob():
    master = generate_master_key()
    blob, kek = make_keyring(master)
    assert kek not in blob


def test_wrong_master_key_cannot_open_keyring():
    blob, _ = make_keyring(generate_master_key())
    with pytest.raises(WrongMasterKeyError):
        open_keyring(generate_master_key(), blob)


def test_tampered_or_truncated_keyring_rejected():
    master = generate_master_key()
    blob, _ = make_keyring(master)
    for i in range(len(blob)):
        bad = bytearray(blob)
        bad[i] ^= 0x01
        with pytest.raises(WrongMasterKeyError):
            open_keyring(master, bytes(bad))
    for bad in (b"", blob[:-1], blob[:10]):
        with pytest.raises(WrongMasterKeyError):
            open_keyring(master, bad)


def test_key_check_accepts_correct_key_only():
    master = generate_master_key()
    check = make_key_check(master)
    assert verify_key_check(master, check) is True
    assert verify_key_check(generate_master_key(), check) is False


def test_key_check_rejects_tampering_and_garbage():
    master = generate_master_key()
    check = make_key_check(master)
    for i in range(len(check)):
        bad = bytearray(check)
        bad[i] ^= 0x01
        assert verify_key_check(master, bytes(bad)) is False
    assert verify_key_check(master, b"") is False
    assert verify_key_check(b"too short", check) is False
    assert verify_key_check(b"x" * 33, check) is False


def test_blobs_are_not_interchangeable():
    master = generate_master_key()
    keyring_blob, _ = make_keyring(master)
    check_blob = make_key_check(master)
    assert verify_key_check(master, keyring_blob) is False
    with pytest.raises(WrongMasterKeyError):
        open_keyring(master, check_blob)


def test_bad_master_key_length_rejected_on_create():
    with pytest.raises(ValueError):
        make_keyring(b"short")
    with pytest.raises(ValueError):
        make_key_check(b"short")


def test_unseal_flow_with_shamir_shares():
    master = generate_master_key()
    check = make_key_check(master)
    shares = split(master, n=5, k=3)
    rebuilt = combine([shares[4], shares[1], shares[2]])
    assert verify_key_check(rebuilt, check) is True


def test_wrong_shares_are_detected_by_key_check():
    master = generate_master_key()
    check = make_key_check(master)
    good = split(master, 5, 3)
    other = split(generate_master_key(), 5, 3)
    try:
        rebuilt = combine([good[0], good[1], other[2]])
    except InvalidSharesError:
        return  # rejected earlier: also fine
    assert verify_key_check(rebuilt, check) is False


def test_kek_from_keyring_works_with_envelope_encryption():
    master = generate_master_key()
    blob, kek = make_keyring(master)
    secret_blob = encrypt_secret(kek, "db/password", 1, b"hunter2")
    reopened_kek = open_keyring(master, blob)
    assert decrypt_secret(reopened_kek, "db/password", 1, secret_blob) == b"hunter2"