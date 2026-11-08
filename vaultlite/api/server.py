"""FastAPI REST API Server for VaultLite.  OWNER: Mohammed Siraj.

This module exposes VaultLite's core security capabilities over standard HTTP/REST.

Endpoints:
    GET    /v1/status           Status of vault (sealed/unsealed, threshold, shares)
    POST   /v1/init             Initialize vault, generate Shamir shares
    POST   /v1/unseal           Submit a custodian unseal share
    POST   /v1/seal             Immediately lock vault, wipe keys from RAM
    PUT    /v1/secret/{path}    Store/update secret (envelope encryption + AAD)
    GET    /v1/secret/{path}    Retrieve decrypted secret
    DELETE /v1/secret/{path}    Delete a secret
    GET    /v1/secrets          List unique secret paths
    POST   /v1/tokens           Generate new API token (admin only)
    POST   /v1/rotate/master    Rotate master key with unseal shares quorum
    POST   /v1/rotate/kek       Rotate KEK and re-wrap secret DEKs
    GET    /v1/audit/verify     Cryptographically verify audit log hash chain & signatures
    GET    /v1/audit/entries    Retrieve audit records (admin only)

Security invariants:
- Secret operations strictly return HTTP 503 while the vault is sealed.
- Plaintext secrets and raw keys are never written to disk or logged.
- All operations are authenticated, authorized via Path ACL, and audit-logged.
"""
import os
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Header, Request, status
from pydantic import BaseModel, Field

from vaultlite.api.auth import AuthManager
from vaultlite.api.policies import (
    CAP_ADMIN,
    CAP_DELETE,
    CAP_LIST,
    CAP_READ,
    CAP_WRITE,
    PolicyEngine,
)
from vaultlite.core.audit import AuditLogger
from vaultlite.core.seal import SealManager, VaultState
from vaultlite.core.storage import Storage
from vaultlite.crypto import envelope
from vaultlite.crypto.errors import (
    DecryptionError,
    InvalidSharesError,
    WrongMasterKeyError,
)

DEFAULT_DB_FILE = os.environ.get("VAULTLITE_DB", "vaultlite.db")


# ------------------------------------------------------------- Request/Response Models
class InitRequest(BaseModel):
    shares: int = Field(default=5, ge=2, le=255, description="Total number of shares to generate (n)")
    threshold: int = Field(default=3, ge=2, le=255, description="Quorum threshold required to unseal (k)")


class InitResponse(BaseModel):
    initialized: bool
    shares: list[str]
    root_token: Optional[str] = None


class UnsealRequest(BaseModel):
    share: str = Field(..., description="Custodian share string (e.g. '1-3a8f...')")


class UnsealResponse(BaseModel):
    state: str
    shares_needed: int
    shares_collected: int


class StatusResponse(BaseModel):
    initialized: bool
    state: str
    threshold: int
    shares_count: int
    shares_collected: int
    shares_needed: int


class SecretPutRequest(BaseModel):
    value: str = Field(..., description="Plaintext secret value to encrypt")


class SecretResponse(BaseModel):
    path: str
    version: int
    value: str


class TokenCreateRequest(BaseModel):
    policy: str = Field(default="dev-read", description="Policy name (root, admin, dev-read, dev-write)")
    description: str = Field(default="", description="Human-readable description for the token")


class TokenCreateResponse(BaseModel):
    token: str
    policy: str
    description: str


class RotateMasterRequest(BaseModel):
    shares: list[str] = Field(..., description="Quorum of custodian shares required to authorize rotation")


class RotateMasterResponse(BaseModel):
    new_shares: list[str]


class RotateKekRequest(BaseModel):
    shares: list[str] = Field(..., description="Quorum of custodian shares required to authorize rotation")


class AuditVerifyResponse(BaseModel):
    valid: bool
    error: Optional[str] = None


# ---------------------------------------------------------------- FastAPI App Factory
def create_app(
    storage: Optional[Storage] = None,
    seal_mgr: Optional[SealManager] = None,
    auth_mgr: Optional[AuthManager] = None,
    audit_logger: Optional[AuditLogger] = None,
) -> FastAPI:
    """Create and configure a VaultLite FastAPI application instance."""
    app = FastAPI(
        title="VaultLite API",
        version="1.0.0",
        description="A Vault-style secrets manager with Shamir Secret Sharing, envelope encryption, and signed audit logging.",
    )

    # State dependencies
    st = storage or Storage(DEFAULT_DB_FILE)
    sm = seal_mgr or SealManager(st)
    pe = PolicyEngine()
    am = auth_mgr or AuthManager(st, pe)
    al = audit_logger or AuditLogger(st)

    app.state.storage = st
    app.state.seal_mgr = sm
    app.state.auth_mgr = am
    app.state.audit_logger = al

    # Helper: Extract bearer token from headers
    def get_token(
        x_vault_token: Optional[str] = Header(None, alias="X-Vault-Token"),
        authorization: Optional[str] = Header(None, alias="Authorization"),
    ) -> Optional[str]:
        if x_vault_token:
            return x_vault_token.strip()
        if authorization and authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return None

    # Helper: Enforce authentication and path-based capability
    def authorize(token: Optional[str], path: str, capability: str) -> dict[str, Any]:
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing authentication token (X-Vault-Token or Authorization: Bearer)",
            )
        token_info = am.validate_token(token)
        if not token_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or revoked authentication token",
            )
        if not am.check_access(token, path, capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"permission denied: token policy '{token_info['policy']}' does not allow '{capability}' on '{path}'",
            )
        return token_info

    # ----------------------------------------------------------- System Endpoints
    @app.get("/v1/status", response_model=StatusResponse)
    def get_status() -> Any:
        """Return the current operational state of the vault."""
        return sm.status()

    @app.post("/v1/init", response_model=InitResponse)
    def initialize_vault(req: InitRequest) -> Any:
        """Initialize the vault, generating and distributing the Shamir unseal shares once."""
        if sm.is_initialized:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="vault is already initialized",
            )
        try:
            shares = sm.initialize(n=req.shares, k=req.threshold)
            # Log initialization (event occurs before unseal, so signed with sealed fallback)
            al.log_event(
                actor="system:init",
                action="vault.initialize",
                path="",
                status=200,
                signing_key=None,
            )
            # Automatically create initial root token for first-time administration
            root_token = am.create_token(policy="root", description="Initial root token created at init")
            # Include root token in shares list for initial operator convenience
            return {"initialized": True, "shares": shares, "root_token": root_token}
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.post("/v1/unseal", response_model=UnsealResponse)
    def unseal_vault(req: UnsealRequest) -> Any:
        """Submit one unseal share. Unlocks the vault once the threshold is reached."""
        if not sm.is_initialized:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="vault is not initialized",
            )
        if sm.is_unsealed:
            return {
                "state": VaultState.UNSEALED.value,
                "shares_needed": 0,
                "shares_collected": 0,
            }

        try:
            new_state, needed = sm.submit_share(req.share)
            signing_key = sm.get_signing_key() if sm.is_unsealed else None
            al.log_event(
                actor="custodian",
                action="vault.unseal",
                path="",
                status=200,
                signing_key=signing_key,
            )
            return {
                "state": new_state.value,
                "shares_needed": needed,
                "shares_collected": sm.shares_collected,
            }
        except (InvalidSharesError, WrongMasterKeyError) as exc:
            al.log_event(
                actor="custodian",
                action="vault.unseal_failed",
                path="",
                status=400,
                signing_key=None,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid unseal share or wrong master key",
            ) from exc

    @app.post("/v1/seal")
    def seal_vault(token: Optional[str] = Depends(get_token)) -> Any:
        """Immediately lock the vault and purge in-memory keys."""
        if not sm.is_unsealed:
            return {"sealed": True, "message": "vault was already sealed"}

        # Require admin permission to seal
        token_info = authorize(token, "sys/seal", CAP_ADMIN)
        signing_key = sm.get_signing_key()
        al.log_event(
            actor=f"token:{token_info['policy']}",
            action="vault.seal",
            path="",
            status=200,
            signing_key=signing_key,
        )
        sm.seal()
        return {"sealed": True, "message": "vault is now sealed; keys wiped from memory"}

    # ----------------------------------------------------------- Secret Endpoints
    @app.put("/v1/secret/{path:path}", response_model=SecretResponse)
    def put_secret(
        path: str,
        req: SecretPutRequest,
        token: Optional[str] = Depends(get_token),
    ) -> Any:
        """Encrypt and store a secret at `path` using envelope encryption (AES-256-GCM + AAD)."""
        if not sm.is_unsealed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="vault is sealed; unseal required before secret operations",
            )

        token_info = authorize(token, path, CAP_WRITE)
        kek = sm.get_kek()
        signing_key = sm.get_signing_key()

        # Compute next version number
        current_version = st.get_latest_version_number(path)
        new_version = current_version + 1

        # Envelope encrypt secret (fresh DEK + fresh nonces + AAD bound to path and version)
        blob = envelope.encrypt_secret(
            kek=kek,
            path=path,
            version=new_version,
            plaintext=req.value.encode("utf-8"),
        )
        st.put_secret(path, new_version, blob)

        al.log_event(
            actor=f"token:{token_info['policy']}",
            action="secret.write",
            path=path,
            status=200,
            signing_key=signing_key,
        )

        return {"path": path, "version": new_version, "value": req.value}

    @app.get("/v1/secret/{path:path}", response_model=SecretResponse)
    def get_secret(
        path: str,
        version: Optional[int] = None,
        token: Optional[str] = Depends(get_token),
    ) -> Any:
        """Retrieve and decrypt the secret at `path`."""
        if not sm.is_unsealed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="vault is sealed; unseal required before secret operations",
            )

        token_info = authorize(token, path, CAP_READ)
        kek = sm.get_kek()
        signing_key = sm.get_signing_key()

        record = st.get_secret(path, version=version)
        if not record:
            al.log_event(
                actor=f"token:{token_info['policy']}",
                action="secret.read_not_found",
                path=path,
                status=404,
                signing_key=signing_key,
            )
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="secret not found")

        ver, blob = record
        try:
            plaintext = envelope.decrypt_secret(kek=kek, path=path, version=ver, blob=blob)
            al.log_event(
                actor=f"token:{token_info['policy']}",
                action="secret.read",
                path=path,
                status=200,
                signing_key=signing_key,
            )
            return {"path": path, "version": ver, "value": plaintext.decode("utf-8")}
        except DecryptionError as exc:
            al.log_event(
                actor=f"token:{token_info['policy']}",
                action="secret.decrypt_error",
                path=path,
                status=400,
                signing_key=signing_key,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="ciphertext tampering detected or decryption failed",
            ) from exc

    @app.delete("/v1/secret/{path:path}")
    def delete_secret(path: str, token: Optional[str] = Depends(get_token)) -> Any:
        """Delete all versions of the secret at `path`."""
        if not sm.is_unsealed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="vault is sealed; unseal required before secret operations",
            )

        token_info = authorize(token, path, CAP_DELETE)
        signing_key = sm.get_signing_key()

        deleted = st.delete_secret(path)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="secret not found")

        al.log_event(
            actor=f"token:{token_info['policy']}",
            action="secret.delete",
            path=path,
            status=200,
            signing_key=signing_key,
        )
        return {"deleted": True, "path": path}

    @app.get("/v1/secrets")
    def list_secrets(token: Optional[str] = Depends(get_token)) -> Any:
        """List all secret paths stored in the vault."""
        if not sm.is_unsealed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="vault is sealed; unseal required before secret operations",
            )

        token_info = authorize(token, "*", CAP_LIST)
        signing_key = sm.get_signing_key()
        all_paths = st.list_secrets()

        al.log_event(
            actor=f"token:{token_info['policy']}",
            action="secrets.list",
            path="",
            status=200,
            signing_key=signing_key,
        )
        return {"secrets": all_paths}

    # ------------------------------------------------------------ Token Endpoints
    @app.post("/v1/tokens", response_model=TokenCreateResponse)
    def create_token(
        req: TokenCreateRequest,
        token: Optional[str] = Depends(get_token),
    ) -> Any:
        """Generate a new API token with an assigned policy. Requires admin permission."""
        if not sm.is_unsealed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="vault is sealed; unseal required",
            )

        token_info = authorize(token, "sys/tokens", CAP_ADMIN)
        signing_key = sm.get_signing_key()

        try:
            raw_token = am.create_token(policy=req.policy, description=req.description)
            al.log_event(
                actor=f"token:{token_info['policy']}",
                action="token.create",
                path=f"policy/{req.policy}",
                status=200,
                signing_key=signing_key,
            )
            return {
                "token": raw_token,
                "policy": req.policy,
                "description": req.description,
            }
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    # --------------------------------------------------------- Rotation Endpoints
    @app.post("/v1/rotate/master", response_model=RotateMasterResponse)
    def rotate_master_key(
        req: RotateMasterRequest,
        token: Optional[str] = Depends(get_token),
    ) -> Any:
        """Rotate the master key and issue 5 new unseal shares."""
        if not sm.is_unsealed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="vault is sealed; unseal required",
            )

        token_info = authorize(token, "sys/rotate", CAP_ADMIN)
        signing_key = sm.get_signing_key()

        try:
            new_shares = sm.rotate_master_key(req.shares)
            al.log_event(
                actor=f"token:{token_info['policy']}",
                action="master.rotate",
                path="",
                status=200,
                signing_key=signing_key,
            )
            return {"new_shares": new_shares}
        except (InvalidSharesError, WrongMasterKeyError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid shares provided for master key rotation",
            ) from exc

    @app.post("/v1/rotate/kek")
    def rotate_kek(
        req: RotateKekRequest,
        token: Optional[str] = Depends(get_token),
    ) -> Any:
        """Rotate the KEK and re-wrap all secret DEKs."""
        if not sm.is_unsealed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="vault is sealed; unseal required",
            )

        token_info = authorize(token, "sys/rotate", CAP_ADMIN)
        signing_key = sm.get_signing_key()

        try:
            sm.rotate_kek(req.shares)
            al.log_event(
                actor=f"token:{token_info['policy']}",
                action="kek.rotate",
                path="",
                status=200,
                signing_key=signing_key,
            )
            return {"rotated": True, "message": "KEK rotated and all secret DEKs re-wrapped successfully"}
        except (InvalidSharesError, WrongMasterKeyError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid shares provided for KEK rotation",
            ) from exc

    # ------------------------------------------------------------ Audit Endpoints
    @app.get("/v1/audit/verify", response_model=AuditVerifyResponse)
    def verify_audit_log(token: Optional[str] = Depends(get_token)) -> Any:
        """Verify the cryptographic hash chain and Ed25519 digital signatures of the audit log."""
        # Verification can be called by anyone or admin to check log integrity
        valid, err = al.verify_chain()
        return {"valid": valid, "error": err}

    @app.get("/v1/audit/entries")
    def get_audit_entries(token: Optional[str] = Depends(get_token)) -> Any:
        """View the raw audit log records. Requires admin permission."""
        authorize(token, "sys/audit", CAP_ADMIN)
        return {"entries": st.get_audit_entries()}

    return app


# Default ASGI application instance for uvicorn
app = create_app()
