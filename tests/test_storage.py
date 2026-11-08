"""Unit tests for the SQLite storage layer.  OWNER: Mohammed Siraj."""
import pytest
from pathlib import Path

from vaultlite.core.storage import Storage


@pytest.fixture
def mem_storage():
    """In-memory storage fixture for fast, clean isolation."""
    storage = Storage(":memory:")
    yield storage
    storage.close()


@pytest.fixture
def file_storage(tmp_path: Path):
    """File-backed storage fixture to test persistence across restarts."""
    db_file = tmp_path / "test_vault.db"
    storage = Storage(db_file)
    yield storage, db_file
    storage.close()


def test_initial_state_empty(mem_storage: Storage):
    assert not mem_storage.is_initialized()
    assert mem_storage.list_secrets() == []
    assert mem_storage.get_meta("keyring_blob") is None


def test_meta_persistence(file_storage):
    storage, db_file = file_storage
    keyring_dummy = b"\x01" + b"\xaa" * 32
    check_dummy = b"\xbb" * 48

    storage.save_meta("keyring_blob", keyring_dummy)
    storage.save_meta("check_blob", check_dummy)

    assert storage.is_initialized()
    assert storage.get_meta("keyring_blob") == keyring_dummy
    assert storage.get_meta("check_blob") == check_dummy
    assert storage.has_meta("keyring_blob")
    assert not storage.has_meta("nonexistent")

    # Close and reopen to verify persistence
    storage.close()
    reopened = Storage(db_file)
    assert reopened.is_initialized()
    assert reopened.get_meta("keyring_blob") == keyring_dummy
    reopened.close()


def test_secret_put_and_get(mem_storage: Storage):
    blob_v1 = b"\x01dummy_ciphertext_blob_v1"
    blob_v2 = b"\x01dummy_ciphertext_blob_v2"

    mem_storage.put_secret("db/password", 1, blob_v1)
    mem_storage.put_secret("db/password", 2, blob_v2)

    # Latest version retrieval
    latest = mem_storage.get_secret("db/password")
    assert latest is not None
    assert latest == (2, blob_v2)
    assert mem_storage.get_latest_version_number("db/password") == 2

    # Specific version retrieval
    v1 = mem_storage.get_secret("db/password", version=1)
    assert v1 == (1, blob_v1)

    v2 = mem_storage.get_secret("db/password", version=2)
    assert v2 == (2, blob_v2)

    # Non-existent version or path
    assert mem_storage.get_secret("db/password", version=99) is None
    assert mem_storage.get_secret("unknown/path") is None
    assert mem_storage.get_latest_version_number("unknown/path") == 0


def test_list_and_delete_secrets(mem_storage: Storage):
    mem_storage.put_secret("api/stripe", 1, b"blob1")
    mem_storage.put_secret("db/postgres", 1, b"blob2")
    mem_storage.put_secret("db/postgres", 2, b"blob3")

    assert mem_storage.list_secrets() == ["api/stripe", "db/postgres"]
    assert mem_storage.list_versions("db/postgres") == [1, 2]

    # Delete secret
    deleted = mem_storage.delete_secret("api/stripe")
    assert deleted is True
    assert mem_storage.list_secrets() == ["db/postgres"]
    assert mem_storage.get_secret("api/stripe") is None

    # Delete non-existent path
    assert mem_storage.delete_secret("api/stripe") is False


def test_update_secret_blob_for_rotation(mem_storage: Storage):
    mem_storage.put_secret("aws/key", 1, b"old_blob")
    mem_storage.update_secret_blob("aws/key", 1, b"new_rewrapped_blob")

    v, blob = mem_storage.get_secret("aws/key", 1)
    assert blob == b"new_rewrapped_blob"

    with pytest.raises(KeyError):
        mem_storage.update_secret_blob("aws/key", 99, b"fail")


def test_get_all_secret_records(mem_storage: Storage):
    mem_storage.put_secret("b/path", 1, b"b1")
    mem_storage.put_secret("a/path", 1, b"a1")
    mem_storage.put_secret("a/path", 2, b"a2")

    records = mem_storage.get_all_secret_records()
    assert len(records) == 3
    assert records[0] == ("a/path", 1, b"a1")
    assert records[1] == ("a/path", 2, b"a2")
    assert records[2] == ("b/path", 1, b"b1")


def test_token_lifecycle(mem_storage: Storage):
    token_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    mem_storage.save_token(token_hash, policy="read-db", description="Dev DB token")
    token = mem_storage.get_token(token_hash)

    assert token is not None
    assert token["policy"] == "read-db"
    assert token["description"] == "Dev DB token"
    assert token["revoked"] is False

    # Revoke
    revoked = mem_storage.revoke_token(token_hash)
    assert revoked is True
    token_after = mem_storage.get_token(token_hash)
    assert token_after["revoked"] is True

    # Revoke non-existent
    assert mem_storage.revoke_token("nonexistent_hash") is False
    assert mem_storage.get_token("nonexistent_hash") is None


def test_audit_log_sequential(mem_storage: Storage):
    seq1 = mem_storage.append_audit_entry(
        actor="custodian-1",
        action="unseal",
        path="",
        status=200,
        link_hash="hash_1",
        signature="sig_1",
    )
    seq2 = mem_storage.append_audit_entry(
        actor="app-backend",
        action="put",
        path="db/password",
        status=201,
        link_hash="hash_2",
        signature="sig_2",
    )

    assert seq1 == 1
    assert seq2 == 2

    entries = mem_storage.get_audit_entries()
    assert len(entries) == 2
    assert entries[0]["seq"] == 1
    assert entries[0]["action"] == "unseal"
    assert entries[0]["link_hash"] == "hash_1"

    assert entries[1]["seq"] == 2
    assert entries[1]["action"] == "put"
    assert entries[1]["path"] == "db/password"


def test_storage_input_validation(mem_storage: Storage):
    with pytest.raises(ValueError, match="path must be a non-empty string"):
        mem_storage.put_secret("", 1, b"blob")

    with pytest.raises(ValueError, match="path must be a non-empty string"):
        mem_storage.get_secret("   ")

    with pytest.raises(ValueError, match="version must be a non-negative integer"):
        mem_storage.put_secret("path", -1, b"blob")

    with pytest.raises(ValueError, match="version must be a non-negative integer"):
        mem_storage.put_secret("path", True, b"blob")  # bool is instance of int in Python

    with pytest.raises(ValueError, match="blob must be non-empty bytes"):
        mem_storage.put_secret("path", 1, b"")
