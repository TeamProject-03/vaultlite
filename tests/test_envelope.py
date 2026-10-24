import pytest

from vaultlite.crypto.envelope import (
    decrypt_secret, encrypt_secret, generate_master_key)
from vaultlite.crypto.errors import DecryptionError


def test_master_key_is_32_random_bytes():
    a, b = generate_master_key(), generate_master_key()
    assert len(a) == 32 and a != b


def test_roundtrip():
    kek = generate_master_key()
    blob = encrypt_secret(kek, "db/password", 1, b"hunter2")
    assert decrypt_secret(kek, "db/password", 1, blob) == b"hunter2"


def test_empty_and_large_plaintext():
    kek = generate_master_key()
    for pt in (b"", b"x" * 100_000):
        blob = encrypt_secret(kek, "p", 1, pt)
        assert decrypt_secret(kek, "p", 1, blob) == pt


def test_plaintext_not_visible_in_blob():
    kek = generate_master_key()
    blob = encrypt_secret(kek, "p", 1, b"super-visible-secret")
    assert b"super-visible-secret" not in blob


def test_fresh_dek_and_nonce_every_time():
    kek = generate_master_key()
    a = encrypt_secret(kek, "p", 1, b"same")
    b = encrypt_secret(kek, "p", 1, b"same")
    assert a != b


def test_wrong_kek_fails():
    blob = encrypt_secret(generate_master_key(), "p", 1, b"x")
    with pytest.raises(DecryptionError):
        decrypt_secret(generate_master_key(), "p", 1, blob)


def test_flipping_any_single_byte_is_detected():
    kek = generate_master_key()
    blob = encrypt_secret(kek, "p", 1, b"integrity matters")
    for i in range(len(blob)):
        bad = bytearray(blob)
        bad[i] ^= 0x01
        with pytest.raises(DecryptionError):
            decrypt_secret(kek, "p", 1, bytes(bad))


def test_blob_cannot_be_moved_to_another_path():
    kek = generate_master_key()
    blob = encrypt_secret(kek, "db/password", 1, b"x")
    with pytest.raises(DecryptionError):
        decrypt_secret(kek, "api/key", 1, blob)


def test_blob_cannot_be_replayed_as_another_version():
    kek = generate_master_key()
    blob = encrypt_secret(kek, "p", 1, b"x")
    with pytest.raises(DecryptionError):
        decrypt_secret(kek, "p", 2, blob)


def test_truncated_or_garbage_blob_fails():
    kek = generate_master_key()
    blob = encrypt_secret(kek, "p", 1, b"x")
    for bad in (b"", b"\x01", blob[:-1], blob[:20], b"\x02" + blob[1:]):
        with pytest.raises(DecryptionError):
            decrypt_secret(kek, "p", 1, bad)


def test_bad_inputs_rejected():
    with pytest.raises(ValueError):
        encrypt_secret(b"short", "p", 1, b"x")
    with pytest.raises(ValueError):
        encrypt_secret(generate_master_key(), "", 1, b"x")
    with pytest.raises(ValueError):
        encrypt_secret(generate_master_key(), "p", -1, b"x")
