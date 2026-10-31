"""Unit tests for the Seal state machine.  OWNER: Student B (Mohammed Siraj)."""
import pytest
from pathlib import Path

from vaultlite.core.seal import SealManager, VaultState
from vaultlite.core.storage import Storage
from vaultlite.crypto import envelope
from vaultlite.crypto.errors import (
    DecryptionError,
    InvalidSharesError,
    WrongMasterKeyError,
)


@pytest.fixture
def storage():
    """In-memory storage fixture."""
    st = Storage(":memory:")
    yield st
    st.close()


@pytest.fixture
def manager(storage: Storage):
    """Fresh SealManager."""
    return SealManager(storage)


def test_initial_uninitialized_state(manager: SealManager):
    assert manager.state == VaultState.UNINITIALIZED
    assert not manager.is_initialized
    assert not manager.is_unsealed
    status = manager.status()
    assert status["state"] == "uninitialized"
    assert status["initialized"] is False

    with pytest.raises(ValueError, match="vault is not initialized"):
        manager.submit_share("1-1234")

    with pytest.raises(RuntimeError, match="vault is sealed"):
        manager.get_kek()


def test_initialize_and_state_transition(manager: SealManager):
    shares = manager.initialize(n=5, k=3)
    assert len(shares) == 5
    assert manager.state == VaultState.SEALED
    assert manager.is_initialized
    assert not manager.is_unsealed
    assert manager.threshold == 3
    assert manager.shares_count == 5

    # Cannot re-initialize
    with pytest.raises(ValueError, match="already initialized"):
        manager.initialize()


def test_unseal_workflow(manager: SealManager):
    shares = manager.initialize(n=5, k=3)

    # Share 1: enters UNSEALING
    state, needed = manager.submit_share(shares[0])
    assert state == VaultState.UNSEALING
    assert needed == 2
    assert manager.shares_collected == 1

    # Duplicate Share 1: deduplicated, still needed == 2
    state, needed = manager.submit_share(shares[0])
    assert state == VaultState.UNSEALING
    assert needed == 2
    assert manager.shares_collected == 1

    # Share 2: needed == 1
    state, needed = manager.submit_share(shares[1])
    assert state == VaultState.UNSEALING
    assert needed == 1

    # Share 3: reaches threshold -> UNSEALED
    state, needed = manager.submit_share(shares[2])
    assert state == VaultState.UNSEALED
    assert needed == 0
    assert manager.is_unsealed
    assert manager.shares_collected == 0

    # KEK is now accessible in memory
    kek = manager.get_kek()
    assert isinstance(kek, bytes)
    assert len(kek) == 32

    # Submitting an extra share while unsealed is a no-op
    state, needed = manager.submit_share(shares[3])
    assert state == VaultState.UNSEALED
    assert needed == 0


def test_seal_purges_memory(manager: SealManager):
    shares = manager.initialize(n=5, k=3)
    for s in shares[:3]:
        manager.submit_share(s)
    assert manager.is_unsealed

    # Seal the vault
    manager.seal()
    assert manager.state == VaultState.SEALED
    assert not manager.is_unsealed

    with pytest.raises(RuntimeError, match="vault is sealed"):
        manager.get_kek()


def test_unseal_with_wrong_shares(storage: Storage):
    manager_a = SealManager(storage)
    shares_a = manager_a.initialize(n=5, k=3)

    storage_b = Storage(":memory:")
    manager_b = SealManager(storage_b)
    shares_b = manager_b.initialize(n=5, k=3)

    # Submit 2 valid shares from A, but 1 foreign share from B
    manager_a.submit_share(shares_a[0])
    manager_a.submit_share(shares_a[1])

    with pytest.raises(WrongMasterKeyError):
        manager_a.submit_share(shares_b[2])

    # Must stay sealed and reset share buffer
    assert manager_a.state == VaultState.SEALED
    assert manager_a.shares_collected == 0
    storage_b.close()


def test_malformed_shares(manager: SealManager):
    manager.initialize()
    with pytest.raises(InvalidSharesError):
        manager.submit_share("not-a-valid-share")


def test_reset_unseal(manager: SealManager):
    shares = manager.initialize(n=5, k=3)
    manager.submit_share(shares[0])
    assert manager.state == VaultState.UNSEALING
    assert manager.shares_collected == 1

    manager.reset_unseal()
    assert manager.state == VaultState.SEALED
    assert manager.shares_collected == 0


def test_master_key_rotation(manager: SealManager, storage: Storage):
    shares = manager.initialize(n=5, k=3)

    # Unseal and store a test secret
    for s in shares[:3]:
        manager.submit_share(s)
    kek_before = manager.get_kek()

    blob = envelope.encrypt_secret(kek_before, "db/password", 1, b"postgres-pass")
    storage.put_secret("db/password", 1, blob)

    # Rotate master key using 3 old shares
    new_shares = manager.rotate_master_key(shares[:3])
    assert len(new_shares) == 5
    assert new_shares != shares

    # Seal and attempt unseal with old shares -> must fail
    manager.seal()
    manager.submit_share(shares[0])
    manager.submit_share(shares[1])
    with pytest.raises(WrongMasterKeyError):
        manager.submit_share(shares[2])

    # Unseal with new shares -> must succeed
    for s in new_shares[:3]:
        manager.submit_share(s)
    assert manager.is_unsealed

    # Secret is still decipherable because KEK didn't change
    kek_after = manager.get_kek()
    assert kek_after == kek_before
    recovered = envelope.decrypt_secret(kek_after, "db/password", 1, blob)
    assert recovered == b"postgres-pass"


def test_kek_rotation(manager: SealManager, storage: Storage):
    shares = manager.initialize(n=5, k=3)
    for s in shares[:3]:
        manager.submit_share(s)
    old_kek = manager.get_kek()

    # Store a secret
    blob_old = envelope.encrypt_secret(old_kek, "api/token", 1, b"sk_test_123")
    storage.put_secret("api/token", 1, blob_old)

    # Rotate KEK
    manager.rotate_kek(shares[:3])
    new_kek = manager.get_kek()
    assert new_kek != old_kek

    # Stored blob should now be re-wrapped with new_kek
    _, rewrapped_blob = storage.get_secret("api/token", 1)
    assert rewrapped_blob != blob_old

    # Decrypt with new KEK succeeds
    plain = envelope.decrypt_secret(new_kek, "api/token", 1, rewrapped_blob)
    assert plain == b"sk_test_123"

    # Decrypt with old KEK fails
    with pytest.raises(DecryptionError):
        envelope.decrypt_secret(old_kek, "api/token", 1, rewrapped_blob)


def test_persistence_across_reboots(tmp_path: Path):
    db_file = tmp_path / "vault.db"
    st1 = Storage(db_file)
    mgr1 = SealManager(st1)
    shares = mgr1.initialize(n=5, k=3)
    st1.close()

    # Simulate restart
    st2 = Storage(db_file)
    mgr2 = SealManager(st2)
    assert mgr2.state == VaultState.SEALED
    assert mgr2.threshold == 3

    # Unseal on new instance
    for s in shares[:3]:
        mgr2.submit_share(s)
    assert mgr2.is_unsealed
    assert len(mgr2.get_kek()) == 32
    st2.close()
