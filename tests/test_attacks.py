import sqlite3
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from vaultlite.api.server import create_app
from vaultlite.core.audit import canonical_payload
from vaultlite.core.storage import Storage
from vaultlite.crypto.envelope import generate_master_key
from vaultlite.crypto.shamir import split
from vaultlite.crypto.signing import GENESIS_HASH, chain_hash

SECRET = "S3cr3t-DB-Passw0rd!"


def unseal(http, shares):
    response = None
    for share in shares:
        response = http.post("/v1/unseal", json={"share": share})
    return response


@pytest.fixture
def vault(tmp_path):
    db_path = tmp_path / "vault.db"
    storage = Storage(db_path)
    with TestClient(create_app(storage=storage)) as http:
        init = http.post("/v1/init", json={"shares": 5, "threshold": 3}).json()
        unseal(http, init["shares"][:3])
        root = {"X-Vault-Token": init["root_token"]}
        stored = http.put("/v1/secret/db/password", json={"value": SECRET}, headers=root)
        assert stored.status_code == 200
        yield SimpleNamespace(
            http=http, db=db_path, shares=init["shares"], token=init["root_token"], root=root
        )
    storage.close()


def attacker_sql(db_path, sql, params=()):
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(sql, params)
        connection.commit()
    finally:
        connection.close()


def read_blob(db_path, path, version=1):
    connection = sqlite3.connect(db_path)
    try:
        row = connection.execute(
            "SELECT blob FROM secrets WHERE path = ? AND version = ?", (path, version)
        ).fetchone()
    finally:
        connection.close()
    return bytes(row[0])


def recompute_chain(db_path):
    connection = sqlite3.connect(db_path)
    try:
        rows = connection.execute(
            "SELECT seq, timestamp, actor, action, path, status FROM audit_log ORDER BY seq"
        ).fetchall()
        link = GENESIS_HASH
        for seq, timestamp, actor, action, path, status in rows:
            link = chain_hash(link, canonical_payload(actor, action, path, status, timestamp))
            connection.execute("UPDATE audit_log SET link_hash = ? WHERE seq = ?", (link, seq))
        connection.commit()
    finally:
        connection.close()


def audit_check(vault):
    return vault.http.get("/v1/audit/verify").json()


def foreign_shares():
    return [share.to_str() for share in split(generate_master_key(), n=5, k=3)]


def test_database_holds_only_ciphertext(vault):
    raw = vault.db.read_bytes()
    assert SECRET.encode() not in raw
    assert vault.token.encode() not in raw
    for share in vault.shares:
        assert share.encode() not in raw


def test_tampered_blob_is_rejected(vault):
    blob = bytearray(read_blob(vault.db, "db/password"))
    blob[len(blob) // 2] ^= 0x01
    attacker_sql(vault.db, "UPDATE secrets SET blob = ? WHERE path = 'db/password'", (bytes(blob),))

    response = vault.http.get("/v1/secret/db/password", headers=vault.root)
    assert response.status_code == 400
    assert "tampering" in response.json()["detail"]
    assert SECRET not in response.text


def test_blob_replayed_under_another_path_is_rejected(vault):
    blob = read_blob(vault.db, "db/password")
    attacker_sql(
        vault.db,
        "INSERT INTO secrets (path, version, blob, created_at) VALUES ('app/stolen', 1, ?, 0)",
        (blob,),
    )

    response = vault.http.get("/v1/secret/app/stolen", headers=vault.root)
    assert response.status_code == 400
    assert SECRET not in response.text


def test_old_version_replayed_as_newer_version_is_rejected(vault):
    vault.http.put("/v1/secret/db/password", json={"value": "new-password"}, headers=vault.root)
    old_blob = read_blob(vault.db, "db/password", version=1)
    attacker_sql(
        vault.db,
        "UPDATE secrets SET blob = ? WHERE path = 'db/password' AND version = 2",
        (old_blob,),
    )

    response = vault.http.get("/v1/secret/db/password", headers=vault.root)
    assert response.status_code == 400


def test_read_only_token_cannot_write(vault):
    created = vault.http.post("/v1/tokens", json={"policy": "dev-read"}, headers=vault.root).json()
    read_only = {"X-Vault-Token": created["token"]}

    assert vault.http.get("/v1/secret/db/password", headers=read_only).status_code == 200
    hacked = vault.http.put("/v1/secret/db/password", json={"value": "hacked"}, headers=read_only)
    assert hacked.status_code == 403
    outside = vault.http.put("/v1/secret/admin/new", json={"value": "x"}, headers=read_only)
    assert outside.status_code == 403
    escalate = vault.http.post("/v1/tokens", json={"policy": "root"}, headers=read_only)
    assert escalate.status_code == 403
    assert vault.http.get("/v1/secret/db/password", headers=vault.root).json()["value"] == SECRET


def test_forged_token_is_rejected(vault):
    forged = {"X-Vault-Token": "s.vaultlite_" + "0" * 64}
    assert vault.http.get("/v1/secret/db/password", headers=forged).status_code == 401


def test_two_shares_are_not_enough(vault):
    vault.http.post("/v1/seal", headers=vault.root)
    response = unseal(vault.http, vault.shares[:2])
    assert response.json()["state"] == "unsealing"
    assert vault.http.get("/v1/secret/db/password", headers=vault.root).status_code == 503


def test_shares_from_another_vault_cannot_unseal(vault):
    vault.http.post("/v1/seal", headers=vault.root)

    response = unseal(vault.http, foreign_shares()[:3])
    assert response.status_code == 400
    assert vault.http.get("/v1/status").json()["state"] == "sealed"
    assert vault.http.get("/v1/secret/db/password", headers=vault.root).status_code == 503


def test_two_real_shares_and_one_fake_cannot_unseal(vault):
    vault.http.post("/v1/seal", headers=vault.root)

    response = unseal(vault.http, [vault.shares[0], vault.shares[1], foreign_shares()[2]])
    assert response.status_code == 400
    assert vault.http.get("/v1/status").json()["state"] == "sealed"
    assert unseal(vault.http, vault.shares[2:5]).json()["state"] == "unsealed"


def test_old_shares_fail_after_master_key_rotation(vault):
    rotated = vault.http.post("/v1/rotate/master", json={"shares": vault.shares[:3]}, headers=vault.root)
    new_shares = rotated.json()["new_shares"]
    vault.http.post("/v1/seal", headers=vault.root)

    assert unseal(vault.http, vault.shares[:3]).status_code == 400
    assert unseal(vault.http, new_shares[:3]).json()["state"] == "unsealed"
    assert vault.http.get("/v1/secret/db/password", headers=vault.root).json()["value"] == SECRET


def test_sealed_vault_refuses_secret_requests(vault):
    vault.http.post("/v1/seal", headers=vault.root)
    assert vault.http.get("/v1/secret/db/password", headers=vault.root).status_code == 503
    assert vault.http.put("/v1/secret/db/x", json={"value": "x"}, headers=vault.root).status_code == 503
    assert vault.http.get("/v1/secrets", headers=vault.root).status_code == 503


def test_edited_audit_entry_is_detected(vault):
    assert audit_check(vault)["valid"] is True
    attacker_sql(vault.db, "UPDATE audit_log SET path = 'app/harmless' WHERE action = 'secret.write'")

    result = audit_check(vault)
    assert result["valid"] is False
    assert "hash chain mismatch" in result["error"]


def test_deleted_audit_entry_is_detected(vault):
    vault.http.get("/v1/secret/db/password", headers=vault.root)
    attacker_sql(vault.db, "DELETE FROM audit_log WHERE action = 'secret.write'")

    assert audit_check(vault)["valid"] is False


def test_edited_entry_with_recomputed_hashes_fails_signature_check(vault):
    vault.http.get("/v1/secret/db/password", headers=vault.root)
    attacker_sql(vault.db, "UPDATE audit_log SET path = 'app/harmless' WHERE action = 'secret.write'")
    recompute_chain(vault.db)

    result = audit_check(vault)
    assert result["valid"] is False
    assert "invalid digital signature" in result["error"]


@pytest.mark.xfail(
    reason="Known limitation: nothing records where the audit chain ends, "
    "so deleting the newest entries is not detected."
)
def test_deleting_the_newest_audit_entry_is_detected(vault):
    attacker_sql(vault.db, "DELETE FROM audit_log WHERE seq = (SELECT MAX(seq) FROM audit_log)")
    assert audit_check(vault)["valid"] is False
