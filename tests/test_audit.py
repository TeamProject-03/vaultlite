"""Unit tests for the tamper-evident audit log and Ed25519 signing.
OWNER: Student B (Mohammed Siraj).
"""
import pytest

from vaultlite.core.audit import AuditLogger, SIG_UNSIGNED_SEALED
from vaultlite.core.seal import SealManager
from vaultlite.core.storage import Storage
from vaultlite.crypto import signing
from vaultlite.crypto.errors import DecryptionError


@pytest.fixture
def storage():
    """In-memory storage fixture."""
    st = Storage(":memory:")
    yield st
    st.close()


@pytest.fixture
def seal_mgr(storage: Storage):
    """SealManager fixture."""
    return SealManager(storage)


@pytest.fixture
def audit_logger(storage: Storage):
    """AuditLogger fixture."""
    return AuditLogger(storage)


# ------------------------------------------------------------- Signing Tests
def test_signing_key_generation_and_verification():
    priv, pub = signing.generate_signing_key()
    msg = "audit-log-payload-sample"

    sig = signing.sign(priv, msg, context=b"audit-entry")
    assert isinstance(sig, str)
    assert len(sig) == 128  # 64 bytes = 128 hex chars in Ed25519

    # Valid signature
    assert signing.verify(pub, msg, sig, context=b"audit-entry") is True

    # Tampered message
    assert signing.verify(pub, msg + "-tampered", sig, context=b"audit-entry") is False

    # Tampered signature
    tampered_sig = ("00" if sig[:2] != "00" else "11") + sig[2:]
    assert signing.verify(pub, msg, tampered_sig, context=b"audit-entry") is False

    # Purpose / context separation: same signature on different context must fail
    assert signing.verify(pub, msg, sig, context=b"different-context") is False


def test_signing_key_wrap_unwrap():
    kek = b"\x07" * 32
    wrong_kek = b"\x08" * 32
    priv, pub = signing.generate_signing_key()

    blob = signing.wrap_signing_key(kek, priv)
    assert isinstance(blob, bytes)

    # Unwrap with correct KEK
    unwrapped = signing.unwrap_signing_key(kek, blob)
    msg = "test-message"
    sig = signing.sign(unwrapped, msg)
    assert signing.verify(pub, msg, sig) is True

    # Unwrap with wrong KEK fails
    with pytest.raises(DecryptionError):
        signing.unwrap_signing_key(wrong_kek, blob)


def test_public_key_hex_serialization():
    _, pub = signing.generate_signing_key()
    hex_str = signing.public_key_to_hex(pub)
    assert len(hex_str) == 64

    recovered_pub = signing.public_key_from_hex(hex_str)
    assert signing.public_key_to_hex(recovered_pub) == hex_str


# ----------------------------------------------------------- Audit Log Tests
def test_audit_empty_log_verification(audit_logger: AuditLogger):
    is_valid, err = audit_logger.verify_chain()
    assert is_valid is True
    assert err is None


def test_audit_logger_end_to_end_signing(
    storage: Storage, seal_mgr: SealManager, audit_logger: AuditLogger
):
    shares = seal_mgr.initialize(n=5, k=3)
    for s in shares[:3]:
        seal_mgr.submit_share(s)
    assert seal_mgr.is_unsealed

    priv_key = seal_mgr.get_signing_key()
    pub_key = seal_mgr.get_signing_public_key()
    assert priv_key is not None
    assert pub_key is not None

    # Log 3 events
    seq1 = audit_logger.log_event("custodian:1", "unseal", status=200, signing_key=priv_key)
    seq2 = audit_logger.log_event("token:admin", "secret.write", path="db/pass", status=200, signing_key=priv_key)
    seq3 = audit_logger.log_event("token:dev", "secret.read", path="db/pass", status=200, signing_key=priv_key)

    assert seq1 == 1
    assert seq2 == 2
    assert seq3 == 3

    # Verify log integrity
    is_valid, err = audit_logger.verify_chain()
    assert is_valid is True
    assert err is None


def test_audit_tamper_payload_detection(
    storage: Storage, seal_mgr: SealManager, audit_logger: AuditLogger
):
    shares = seal_mgr.initialize(n=5, k=3)
    for s in shares[:3]:
        seal_mgr.submit_share(s)
    priv = seal_mgr.get_signing_key()

    audit_logger.log_event("custodian:1", "unseal", status=200, signing_key=priv)
    audit_logger.log_event("token:attacker", "secret.read", path="db/pass", status=200, signing_key=priv)
    audit_logger.log_event("token:dev", "secret.read", path="app/conf", status=200, signing_key=priv)

    # Simulate attack: attacker modifies the SQLite row to cover their tracks
    with storage._conn:
        storage._conn.execute(
            "UPDATE audit_log SET actor = 'token:legitimate' WHERE seq = 2"
        )

    # Verification must catch the tampering and point directly to sequence 2
    is_valid, err = audit_logger.verify_chain()
    assert is_valid is False
    assert "hash chain mismatch at sequence 2" in err


def test_audit_tamper_signature_detection(
    storage: Storage, seal_mgr: SealManager, audit_logger: AuditLogger
):
    shares = seal_mgr.initialize(n=5, k=3)
    for s in shares[:3]:
        seal_mgr.submit_share(s)
    priv = seal_mgr.get_signing_key()

    audit_logger.log_event("admin", "init", status=200, signing_key=priv)
    audit_logger.log_event("admin", "rotate", status=200, signing_key=priv)

    # Corrupt the signature of sequence 1
    with storage._conn:
        storage._conn.execute(
            "UPDATE audit_log SET signature = '00' || SUBSTR(signature, 3) WHERE seq = 1"
        )

    is_valid, err = audit_logger.verify_chain()
    assert is_valid is False
    assert "invalid digital signature at sequence 1" in err


def test_audit_tamper_row_deletion_detection(
    storage: Storage, seal_mgr: SealManager, audit_logger: AuditLogger
):
    shares = seal_mgr.initialize(n=5, k=3)
    for s in shares[:3]:
        seal_mgr.submit_share(s)
    priv = seal_mgr.get_signing_key()

    audit_logger.log_event("actor:1", "action:1", status=200, signing_key=priv)
    audit_logger.log_event("actor:2", "action:2", status=200, signing_key=priv)
    audit_logger.log_event("actor:3", "action:3", status=200, signing_key=priv)

    # Delete row 2
    with storage._conn:
        storage._conn.execute("DELETE FROM audit_log WHERE seq = 2")

    # Verification must detect chain breakage
    is_valid, err = audit_logger.verify_chain()
    assert is_valid is False
    assert "hash chain mismatch at sequence 3" in err


def test_audit_sealed_events(audit_logger: AuditLogger):
    # Vault is sealed (no signing key)
    seq = audit_logger.log_event("custodian:1", "unseal_attempt", status=400, signing_key=None)
    assert seq == 1

    entries = audit_logger._storage.get_audit_entries()
    assert entries[0]["signature"] == SIG_UNSIGNED_SEALED

    # Hash chain should still verify properly
    is_valid, err = audit_logger.verify_chain()
    assert is_valid is True
    assert err is None
