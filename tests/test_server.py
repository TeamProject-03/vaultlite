"""Integration tests for the FastAPI REST server.  OWNER: Mohammed Siraj."""
import pytest
from fastapi.testclient import TestClient

from vaultlite.api.server import create_app
from vaultlite.core.seal import SealManager
from vaultlite.core.storage import Storage


@pytest.fixture
def client():
    """Create a test client backed by an isolated in-memory database."""
    storage = Storage(":memory:")
    app = create_app(storage=storage)
    with TestClient(app) as test_client:
        yield test_client
    storage.close()


def test_initial_status(client: TestClient):
    res = client.get("/v1/status")
    assert res.status_code == 200
    data = res.json()
    assert data["initialized"] is False
    assert data["state"] == "uninitialized"


def test_init_and_idempotency(client: TestClient):
    # Initialize vault
    res = client.post("/v1/init", json={"shares": 5, "threshold": 3})
    assert res.status_code == 200
    data = res.json()
    assert data["initialized"] is True
    assert len(data["shares"]) == 5
    assert "root_token" in data
    assert data["root_token"].startswith("s.vaultlite_")

    # Second initialization attempt must be rejected
    res2 = client.post("/v1/init", json={"shares": 5, "threshold": 3})
    assert res2.status_code == 400
    assert "already initialized" in res2.json()["detail"]


def test_unseal_progression(client: TestClient):
    init_res = client.post("/v1/init", json={"shares": 5, "threshold": 3}).json()
    shares = init_res["shares"]

    # Submit share 1
    res1 = client.post("/v1/unseal", json={"share": shares[0]})
    assert res1.status_code == 200
    assert res1.json()["state"] == "unsealing"
    assert res1.json()["shares_needed"] == 2

    # Submit bad share
    res_bad = client.post("/v1/unseal", json={"share": "invalid-share-string"})
    assert res_bad.status_code == 400

    # Submit share 2
    res2 = client.post("/v1/unseal", json={"share": shares[1]})
    assert res2.status_code == 200
    assert res2.json()["shares_needed"] == 1

    # Submit share 3 (reaches threshold -> UNSEALED)
    res3 = client.post("/v1/unseal", json={"share": shares[2]})
    assert res3.status_code == 200
    assert res3.json()["state"] == "unsealed"
    assert res3.json()["shares_needed"] == 0

    # Check status
    status = client.get("/v1/status").json()
    assert status["state"] == "unsealed"


def test_secret_operations_barrier_while_sealed(client: TestClient):
    init_res = client.post("/v1/init", json={"shares": 5, "threshold": 3}).json()
    root_token = init_res["root_token"]

    # Vault is sealed: operations must return HTTP 503
    headers = {"X-Vault-Token": root_token}
    res_put = client.put("/v1/secret/db/password", json={"value": "secret"}, headers=headers)
    assert res_put.status_code == 503
    assert "vault is sealed" in res_put.json()["detail"]

    res_get = client.get("/v1/secret/db/password", headers=headers)
    assert res_get.status_code == 503


def test_secret_lifecycle_and_versioning(client: TestClient):
    init_res = client.post("/v1/init", json={"shares": 5, "threshold": 3}).json()
    shares = init_res["shares"]
    root_token = init_res["root_token"]
    headers = {"X-Vault-Token": root_token}

    # Unseal
    for s in shares[:3]:
        client.post("/v1/unseal", json={"share": s})

    # Store version 1
    p1 = client.put("/v1/secret/db/password", json={"value": "pass_v1"}, headers=headers)
    assert p1.status_code == 200
    assert p1.json()["version"] == 1

    # Store version 2
    p2 = client.put("/v1/secret/db/password", json={"value": "pass_v2"}, headers=headers)
    assert p2.status_code == 200
    assert p2.json()["version"] == 2

    # Read latest (v2)
    g_latest = client.get("/v1/secret/db/password", headers=headers)
    assert g_latest.status_code == 200
    assert g_latest.json()["value"] == "pass_v2"
    assert g_latest.json()["version"] == 2

    # Read specific (v1)
    g_v1 = client.get("/v1/secret/db/password?version=1", headers=headers)
    assert g_v1.status_code == 200
    assert g_v1.json()["value"] == "pass_v1"

    # List secrets
    l_res = client.get("/v1/secrets", headers=headers)
    assert l_res.status_code == 200
    assert "db/password" in l_res.json()["secrets"]

    # Delete secret
    d_res = client.delete("/v1/secret/db/password", headers=headers)
    assert d_res.status_code == 200
    assert d_res.json()["deleted"] is True

    # Get after delete -> 404
    g_404 = client.get("/v1/secret/db/password", headers=headers)
    assert g_404.status_code == 404


def test_token_and_policy_enforcement(client: TestClient):
    init_res = client.post("/v1/init", json={"shares": 5, "threshold": 3}).json()
    shares = init_res["shares"]
    root_token = init_res["root_token"]

    for s in shares[:3]:
        client.post("/v1/unseal", json={"share": s})

    # Create dev-read token using root token
    res_tok = client.post(
        "/v1/tokens",
        json={"policy": "dev-read", "description": "Backend Read Token"},
        headers={"X-Vault-Token": root_token},
    )
    assert res_tok.status_code == 200
    read_token = res_tok.json()["token"]

    # First write a secret as root
    client.put("/v1/secret/db/password", json={"value": "db_secret"}, headers={"X-Vault-Token": root_token})

    # dev-read token reads db/password -> 200 OK
    res_read = client.get("/v1/secret/db/password", headers={"X-Vault-Token": read_token})
    assert res_read.status_code == 200
    assert res_read.json()["value"] == "db_secret"

    # dev-read token attempts to write db/password -> 403 Forbidden
    res_write = client.put("/v1/secret/db/password", json={"value": "new"}, headers={"X-Vault-Token": read_token})
    assert res_write.status_code == 403
    assert "permission denied" in res_write.json()["detail"]

    # dev-read token attempts to access unlisted path sys/tokens -> 403 Forbidden
    res_forbidden = client.get("/v1/secret/sys/tokens", headers={"X-Vault-Token": read_token})
    assert res_forbidden.status_code == 403

    # Missing token -> 401 Unauthorized
    res_unauth = client.get("/v1/secret/db/password")
    assert res_unauth.status_code == 401


def test_seal_endpoint(client: TestClient):
    init_res = client.post("/v1/init", json={"shares": 5, "threshold": 3}).json()
    shares = init_res["shares"]
    root_token = init_res["root_token"]
    headers = {"X-Vault-Token": root_token}

    for s in shares[:3]:
        client.post("/v1/unseal", json={"share": s})
    assert client.get("/v1/status").json()["state"] == "unsealed"

    # Seal the vault
    res_seal = client.post("/v1/seal", headers=headers)
    assert res_seal.status_code == 200
    assert res_seal.json()["sealed"] is True

    # State is now sealed
    assert client.get("/v1/status").json()["state"] == "sealed"

    # Secret operations now fail with 503
    assert client.get("/v1/secret/db/pass", headers=headers).status_code == 503


def test_master_and_kek_rotation(client: TestClient):
    init_res = client.post("/v1/init", json={"shares": 5, "threshold": 3}).json()
    shares = init_res["shares"]
    root_token = init_res["root_token"]
    headers = {"X-Vault-Token": root_token}

    for s in shares[:3]:
        client.post("/v1/unseal", json={"share": s})

    # Store a secret
    client.put("/v1/secret/api/key", json={"value": "stripe_live_123"}, headers=headers)

    # Rotate master key
    rot_master = client.post("/v1/rotate/master", json={"shares": shares[:3]}, headers=headers)
    assert rot_master.status_code == 200
    new_shares = rot_master.json()["new_shares"]
    assert len(new_shares) == 5
    assert new_shares != shares

    # Rotate KEK
    rot_kek = client.post("/v1/rotate/kek", json={"shares": new_shares[:3]}, headers=headers)
    assert rot_kek.status_code == 200
    assert rot_kek.json()["rotated"] is True

    # Secret is still readable
    sec = client.get("/v1/secret/api/key", headers=headers)
    assert sec.status_code == 200
    assert sec.json()["value"] == "stripe_live_123"


def test_audit_verification_endpoint(client: TestClient):
    init_res = client.post("/v1/init", json={"shares": 5, "threshold": 3}).json()
    shares = init_res["shares"]
    root_token = init_res["root_token"]
    headers = {"X-Vault-Token": root_token}

    for s in shares[:3]:
        client.post("/v1/unseal", json={"share": s})

    client.put("/v1/secret/db/pwd", json={"value": "secret1"}, headers=headers)
    client.get("/v1/secret/db/pwd", headers=headers)

    # Verify audit chain via API
    v_res = client.get("/v1/audit/verify")
    assert v_res.status_code == 200
    assert v_res.json()["valid"] is True
    assert v_res.json()["error"] is None

    # Retrieve entries
    e_res = client.get("/v1/audit/entries", headers=headers)
    assert e_res.status_code == 200
    assert len(e_res.json()["entries"]) >= 4
