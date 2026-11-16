# VaultLite threat model

All threats we studied, protection provided by the system, how they are being tested and the remaining risk. It uses the categories of STRIDE: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service and Elevation of privilege.

The scope is the prototype when it is running in the demo: one TLS certificate (from our own private CA, `scripts/make_ca.py`), one SQLite file (`vaultlite.db`), one server process (`vaultlite/api/server.py`) and the command line client (`vaultlite/cli.py`).

## 1. What we protect

| Asset | Where it resides | Protection when at rest |
|---|---|---|
| Secret values | `secrets` | AES-256-GCM version-wise with new data key (DEK) |
| Master key | NOT stored anywhere | Divided into 5 shamir shares |
| Vault key (KEK) | Server RAM while unsealed; `keyring_blob` | Encrypted with key derived from the master key |
| Audit signing key (Ed25519) | Server RAM while unsealed; `signing_blob` | Encrypted under the KEK |
| API tokens | stored by user; table: `tokens` | only hash (SHA-256) is stored |
| Audit log integrity | `audit_log` table | hash chain and Ed25519 signatures |
| UNSEAL shares | 5 custodians, each with their own share | any 3 of the shares can be used to reconstruct the master key, but 2 shares cannot be used to reconstruct the key |

## 2. With whom we fight

| ID | Attacker | What they can do |
|---|---|---|
| A1 | Network attacker | see or change the traffic of the CLI and the server or pretend to be the server |
| A2 | Thief of the database file | Read an offline copy of `vaultlite.db` file |
| A3 | Attacker with the ability to modify the database file | Modify, copy or delete rows in `vaultlite.db` |
| A4 | Insider with a low privilege token | Any request with a `dev-read` token |
| A5 | Custodian or outsider with fake or too few shares | Call `/v1/unseal`, which doesn't require a token |
| A6 | Attacker can control the running server | Out of scope: Can read keys off memory |

Trust boundaries: The network between CLI and server is the untrusted network and thus is protected by TLS. All sensitive information in the database file will be encrypted/hashed and the database file will be untrusted storage. While the vault is unsealed, the keys are stored in the server memory, which is trusted; this is a limitation (see G10 for details).

## 3. Threats, defences and evidence

Test names are the names of the files in `tests/`, for example `test_attacks: test_tampered_blob_is_rejected`.

| ID | STRIDE | Threat | Defence in VaultLite | Evidence | Remaining risk |
|---|---|---|---|---|---|
| S1 | Spoofing | A4 guesses or forges an API token | Tokens are 256 random bits from `secrets`; only the hash of the token is stored; the `hmac.compare_digest` function is used for comparisons | `test_attacks: test_forged_token_is_rejected`, `test_cli: test_wrong_token_is_rejected`, `test_auth_policies: test_token_validation` | Stealing a token is possible until revocation; no endpoint for revocation and no expiry (G7) |
| S2 | Spoofing | A1 pretends to be the server | TLS with our private CA; the CLI trusts only `certs/ca.crt`, checks the host name and refuses anything below TLS 1.3 | Checked live: a certificate from another CA gives "TLS check failed"; `test_cli: test_missing_ca_certificate_is_reported` | No mutual TLS, so the server cannot identify clients by certificate. Not encrypted private key (CA) (G9) |
| S3 | Spoofing | A5 tries to unlock the vault with shares from another vault, or with 2 real shares plus 1 fake | The key-check blob lets the server know whether the reconstructed master key is correct or not, so the vault stays sealed | `test_attacks: test_shares_from_another_vault_cannot_unseal`, `test_attacks: test_two_real_shares_and_one_fake_cannot_unseal`, `test_keyring: test_wrong_shares_are_detected_by_key_check` | A fake share resets the progress of an unseal (G4) |
| T1 | Tampering | A3 modification of secret bytes after they are stored | AES-256-GCM and authentication tag will fail to decrypt with HTTP 400 if any of its bytes are modified | `test_attacks: test_tampered_blob_is_rejected`, `test_envelope: test_flipping_any_single_byte_is_detected` | None found |
| T2 | Tampering | A3 copies a blob to another path, or puts an old version in place of a newer one | Path and version are authenticated as AAD, so a moved or replayed blob fails to decrypt | `test_attacks: test_blob_replayed_under_another_path_is_rejected`, `test_attacks: test_old_version_replayed_as_newer_version_is_rejected`, `test_envelope: test_blob_cannot_be_moved_to_another_path` | If the newest version is deleted, the server returns the old value of a blob, no error (G2) |
| T3 | Tampering | A3 manipulates an audit entry in the middle of the log such that the chain is broken | Each entry's link is SHA-256 of the previous link and the entry itself, so the chain breaks | `test_attacks: test_edited_audit_entry_is_detected`, `test_attacks: test_deleted_audit_entry_is_detected`, `test_audit: test_audit_tamper_payload_detection` | See T5 |
| T4 | Tampering | A3 edits an entry and recomputes every later hash | Each link is signed with Ed25519, if the signing key is not available, then the new links cannot be signed | `test_attacks: test_edited_entry_with_recomputed_hashes_fails_signature_check`, `test_audit: test_audit_tamper_signature_detection` | Entries written while sealed are unsigned and only protected by the hash chain |
| T5 | Tampering | A3 deletes the most recent audit entries | Not defended | `test_attacks: test_deleting_the_newest_audit_entry_is_detected` is xfailed | No marking of end of chain (G1) |
| T6 | Tampering | A3 restore full database with old version | Not defended | Reasoned from the design | Old secret values, old shares and an old (but valid) audit log are restored (G3) |
| T7 | Tampering | A3 damages or swaps the keyring or key-check blob | Each blob is encrypted with its own HKDF subkey, so damaged or swapped blobs are rejected | `test_keyring: test_tampered_or_truncated_keyring_rejected`, `test_keyring: test_blobs_are_not_interchangeable` | A damaged or swapped keyring or key-check blob will cause the vault to be inaccessible until the blob is restored from backup |
| R1 | Repudiation | A user denies reading or writing a secret | Every request (actor, action, path, status and time) is logged and each logged request is signed with Ed25519 while the vault is unsealed | `test_cli: test_audit_verify_and_list`, `test_audit: test_audit_logger_end_to_end_signing` | The actor is the policy name (e.g., `token:root`) and multiple users with the same root policy look the same (G5) |
| I1 | Information disclosure | A2 reads a stolen copy of the database | Secret values are encrypted; the KEK and the signing key are encrypted; tokens are hashed; the master key is never stored | `test_attacks: test_database_holds_only_ciphertext`, `test_envelope: test_plaintext_not_visible_in_blob`, `test_keyring: test_kek_not_visible_in_keyring_blob` | Secret paths, version numbers, timestamps and the audit log are readable (G8) |
| I2 | Information disclosure | A1 eavesdrops on CLI traffic | HTTPS; the CLI only supports TLS 1.3 | Handshake supported TLSv1.3 (checked live) | The server still supports TLS 1.2 with other clients (G6) |
| I3 | Information disclosure | A5 has less than 3 shares | Shamir's scheme over the prime field 2^521 - 1: 2 shares reveal nothing about the master key | `test_shamir: test_two_shares_do_not_reveal_secret`, `test_attacks: test_two_shares_are_not_enough` | A custodian can disclose his/her share, or 3 custodians can collude and open the vault |
| I4 | Information disclosure | Secrets could be disclosed in shell history, in logs or in error messages | The CLI prompts for shares and values at a hidden prompt, and the server does not log secrets, only returns generic error messages | Code review; `test_cli: test_put_and_get_with_versions` covers the hidden prompt | `put PATH VALUE` with the value typed in the command goes into shell history. In the demo all shares reside in one file called `shares.txt`; in real use, this should not be done |
| I5 | Information disclosure | Keys are read from the server memory | The KEK and signing key are stored in RAM only and are dropped on seal | `test_seal: test_seal_purges_memory` | They can be read by A6 while unsealed (G10), Python can not reliably wipe the memory |
| D1 | Denial of service | A5 sends a fake share during unseal | Not defended | Checked live: one fake share reset the collected shares to 0 | Anyone who can reach the server can keep the vault sealed (G4) |
| D2 | Denial of service | Shares are lost | By design, 3 out of 5 shares are enough to recover the data | `test_shamir: test_any_3_of_5_rebuild_secret` | If 3 or more shares are lost, the data can no longer be recovered |
| D3 | Denial of service | Server restart | by design, the vault restarts sealed, and requires 3 persons to re-open it again | `test_seal: test_persistence_across_reboots` | Each restart requires 3 persons to re-open the vault again. There is no rate limiting on any endpoint |
| E1 | Elevation of privilege | A4 writes, or creates a root token, with a read-only token | Path policies with default deny; creating tokens, sealing and rotating need the admin capability | `test_attacks: test_read_only_token_cannot_write`, `test_cli: test_read_only_token_cannot_write`, `test_server: test_token_and_policy_enforcement` | The root token from `init` never expires (G7) |
| E2 | Elevation of privilege | Anyone reads secrets while vault is sealed | Secret endpoints refuse to return any secrets when vault is sealed; KEK is not in memory | `test_attacks: test_sealed_vault_refuses_secret_requests`, `test_server: test_secret_operations_barrier_while_sealed` | None found |
| E3 | Elevation of privilege | Old shares or leaked shares are used after a rotation | Old shares stop working after master-key rotation; rotation needs an admin token and 3 current shares | `test_attacks: test_old_shares_fail_after_master_key_rotation`, `test_rotation: test_old_master_and_old_shares_stop_working` | If data has been decrypted in the past using old shares or leaked shares, then it is not protected by rotation |

## 4. Suggested solutions for the identified gaps based on the results of the tests performed

| ID | Gap | Possible fix |
|---|---|---|
| G1 | The deletion of "newest" audit entries is not detected | Signed checkpoint to store latest link hash, number of entries in the log, or copy the log to another machine |
| G2 | Silent deletion of the newest version switches a secret back to its previous version | Maintain signed record of most up-to-date version of a secret path for every secret and check it on each read |
| G3 | If older copy of entire database is restored, the restoration is not detected | Maintain a counter or signed checkpoint outside of the database file |
| G4 | `/v1/unseal` does not require a login, and one fake share resets the progress | Rate-limit unseal attempts, and require identification of custodians before accepting a share. |
| G5 | Policy name only is recorded in audit log, no token identifier | Record a short token identifier (first 8 chars of hash, or description) |
| G6 | The server still supports TLS 1.2 | Start the server with a minimum TLS version of 1.3 |
| G7 | Tokens never expire and can not be revoked using the API | Add an expiry time and a revoke endpoint (`AuthManager.revoke_token` is available) |
| G8 | Secret paths, versions and audit information are stored in clear text | Encrypt secret paths, versions and audit information, or accept it as metadata leakage |
| G9 | CA private key is kept in plain text in `certs/` | Encrypt with a passphrase or keep CA offline after creating server certificate |
| G10 | Keys are stored in server memory when the vault is unlocked | Lock and wipe key memory (using a language that supports it or a hardware security module (HSM)) |

## 5. How to reproduce

Run all ATTACK tests. To run tests, use the command:

```bash
python -m pytest tests/test_attacks.py -v
```

Run the attacks manually on the running server (from project folder):

```bash
python scripts/attack_demo.py show-db
```

To tamper with a stored blob, execute the following command:

```bash
python scripts/attack_demo.py tamper-blob db/password
```

To replay a stored blob under another path, use the following command:

```bash
python scripts/attack_demo.py replay-blob app/api-key db/backup
```

```bash
python scripts/attack_demo.py edit-audit
```

After every attack, you can view the vault's detection of the attack by running `python -m vaultlite.cli get ...` or `python -m vaultlite.cli audit-verify`.
