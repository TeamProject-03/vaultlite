"""SQLite encrypted storage layer for VaultLite.  OWNER: Student B (Mohammed Siraj).

This module handles all database persistence for the vault.

Security invariants:
- The database stores ONLY ciphertext, wrapped keys, hashed tokens, and
  signed audit entries.
- Plaintext secrets, raw data encryption keys (DEKs), and raw master keys
  are NEVER written to disk.
- Tokens are stored exclusively as cryptographic hashes (SHA-256).

Tables:
- vault_meta: stores keyring_blob, check_blob, signing_blob, signing_pub_hex
- secrets: stores path, version, encrypted blob (from envelope.py), timestamp
- tokens: stores token_hash, policy name, description, created_at, revoked flag
- audit_log: stores append-only chained audit entries and Ed25519 signatures
"""
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional


def _check_path(path: str) -> None:
    if not isinstance(path, str) or not path.strip():
        raise ValueError("path must be a non-empty string")


def _check_version(version: int) -> None:
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        raise ValueError("version must be a non-negative integer")


def _check_bytes(data: bytes, name: str) -> None:
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
        raise ValueError(f"{name} must be non-empty bytes")


class Storage:
    """Manages SQLite persistence for VaultLite."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        # check_same_thread=False allows FastAPI multithreaded request handling
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self) -> None:
        """Create database schema if it does not already exist."""
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS vault_meta (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS secrets (
                    path TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    blob BLOB NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (path, version)
                );

                CREATE INDEX IF NOT EXISTS idx_secrets_path 
                ON secrets(path);

                CREATE TABLE IF NOT EXISTS tokens (
                    token_hash TEXT PRIMARY KEY,
                    policy TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status INTEGER NOT NULL,
                    link_hash TEXT NOT NULL,
                    signature TEXT NOT NULL
                );
                """
            )

    # ------------------------------------------------------------- vault_meta
    def save_meta(self, key: str, value: bytes) -> None:
        """Store or replace an encrypted metadata blob (e.g. keyring_blob)."""
        _check_path(key)
        _check_bytes(value, "value")
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
                (key, bytes(value)),
            )

    def get_meta(self, key: str) -> Optional[bytes]:
        """Retrieve a metadata blob by key, or None if not found."""
        _check_path(key)
        cursor = self._conn.execute(
            "SELECT value FROM vault_meta WHERE key = ?", (key,)
        )
        row = cursor.fetchone()
        return bytes(row["value"]) if row else None

    def has_meta(self, key: str) -> bool:
        """Return True if metadata exists for the given key."""
        return self.get_meta(key) is not None

    def is_initialized(self) -> bool:
        """Return True if the vault has been initialized (keyring exists)."""
        return self.has_meta("keyring_blob") and self.has_meta("check_blob")

    # ---------------------------------------------------------------- secrets
    def put_secret(self, path: str, version: int, blob: bytes) -> None:
        """Store an encrypted secret blob for a given path and version.

        The blob must be the ciphertext produced by envelope.encrypt_secret.
        """
        _check_path(path)
        _check_version(version)
        _check_bytes(blob, "blob")
        now = time.time()
        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO secrets (path, version, blob, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (path, version, bytes(blob), now),
            )

    def get_secret(
        self, path: str, version: Optional[int] = None
    ) -> Optional[tuple[int, bytes]]:
        """Retrieve a secret blob.

        If version is None, returns the latest version (version, blob).
        If version is specified, returns that specific version (version, blob).
        Returns None if no matching secret exists.
        """
        _check_path(path)
        if version is not None:
            _check_version(version)
            cursor = self._conn.execute(
                "SELECT version, blob FROM secrets WHERE path = ? AND version = ?",
                (path, version),
            )
        else:
            cursor = self._conn.execute(
                """
                SELECT version, blob FROM secrets 
                WHERE path = ? 
                ORDER BY version DESC LIMIT 1
                """,
                (path,),
            )
        row = cursor.fetchone()
        if not row:
            return None
        return int(row["version"]), bytes(row["blob"])

    def get_latest_version_number(self, path: str) -> int:
        """Return the highest version number for path, or 0 if none exist."""
        _check_path(path)
        cursor = self._conn.execute(
            "SELECT MAX(version) AS max_v FROM secrets WHERE path = ?", (path,)
        )
        row = cursor.fetchone()
        if not row or row["max_v"] is None:
            return 0
        return int(row["max_v"])

    def list_secrets(self) -> list[str]:
        """Return a sorted list of unique secret paths stored in the vault."""
        cursor = self._conn.execute(
            "SELECT DISTINCT path FROM secrets ORDER BY path ASC"
        )
        return [str(row["path"]) for row in cursor.fetchall()]

    def list_versions(self, path: str) -> list[int]:
        """Return all stored version numbers for a given path, sorted ascending."""
        _check_path(path)
        cursor = self._conn.execute(
            "SELECT version FROM secrets WHERE path = ? ORDER BY version ASC",
            (path,),
        )
        return [int(row["version"]) for row in cursor.fetchall()]

    def delete_secret(self, path: str) -> bool:
        """Delete all versions of a secret at the given path.

        Returns True if at least one row was deleted.
        """
        _check_path(path)
        with self._conn:
            cursor = self._conn.execute(
                "DELETE FROM secrets WHERE path = ?", (path,)
            )
            return cursor.rowcount > 0

    def update_secret_blob(self, path: str, version: int, new_blob: bytes) -> None:
        """Update the encrypted blob of an existing secret version (used during KEK rotation)."""
        _check_path(path)
        _check_version(version)
        _check_bytes(new_blob, "new_blob")
        with self._conn:
            cursor = self._conn.execute(
                "UPDATE secrets SET blob = ? WHERE path = ? AND version = ?",
                (bytes(new_blob), path, version),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"secret '{path}' version {version} not found")

    def get_all_secret_records(self) -> list[tuple[str, int, bytes]]:
        """Return all (path, version, blob) records in the database (for key rotation)."""
        cursor = self._conn.execute(
            "SELECT path, version, blob FROM secrets ORDER BY path, version ASC"
        )
        return [(str(r["path"]), int(r["version"]), bytes(r["blob"])) for r in cursor.fetchall()]

    # ----------------------------------------------------------------- tokens
    def save_token(
        self, token_hash: str, policy: str, description: str = ""
    ) -> None:
        """Store a token's SHA-256 hash and its associated policy."""
        _check_path(token_hash)
        _check_path(policy)
        now = time.time()
        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO tokens (token_hash, policy, description, created_at, revoked)
                VALUES (?, ?, ?, ?, 0)
                """,
                (token_hash, policy, description, now),
            )

    def get_token(self, token_hash: str) -> Optional[dict[str, Any]]:
        """Look up a token by its SHA-256 hash. Returns dict or None."""
        _check_path(token_hash)
        cursor = self._conn.execute(
            """
            SELECT token_hash, policy, description, created_at, revoked
            FROM tokens WHERE token_hash = ?
            """,
            (token_hash,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "token_hash": str(row["token_hash"]),
            "policy": str(row["policy"]),
            "description": str(row["description"]),
            "created_at": float(row["created_at"]),
            "revoked": bool(row["revoked"]),
        }

    def revoke_token(self, token_hash: str) -> bool:
        """Mark a token as revoked. Returns True if token was active and now revoked."""
        _check_path(token_hash)
        with self._conn:
            cursor = self._conn.execute(
                "UPDATE tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0",
                (token_hash,),
            )
            return cursor.rowcount > 0

    # -------------------------------------------------------------- audit log
    def append_audit_entry(
        self,
        actor: str,
        action: str,
        path: str,
        status: int,
        link_hash: str,
        signature: str,
        timestamp: Optional[float] = None,
    ) -> int:
        """Append a tamper-evident audit record and return its sequence number."""
        now = time.time() if timestamp is None else timestamp
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO audit_log (
                    timestamp, actor, action, path, status, link_hash, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (now, actor, action, path, int(status), link_hash, signature),
            )
            return int(cursor.lastrowid)

    def get_audit_entries(self) -> list[dict[str, Any]]:
        """Return all audit log records ordered by sequence number ascending."""
        cursor = self._conn.execute(
            """
            SELECT seq, timestamp, actor, action, path, status, link_hash, signature
            FROM audit_log ORDER BY seq ASC
            """
        )
        return [
            {
                "seq": int(r["seq"]),
                "timestamp": float(r["timestamp"]),
                "actor": str(r["actor"]),
                "action": str(r["action"]),
                "path": str(r["path"]),
                "status": int(r["status"]),
                "link_hash": str(r["link_hash"]),
                "signature": str(r["signature"]),
            }
            for r in cursor.fetchall()
        ]

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()
