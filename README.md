# VaultLite

VaultLite is a little secrets manager like HashiCorp Vault for the MACS 902 group project. Applications and humans store passwords, API keys and other secrets in the vault rather than in the code or in the chat and retrieve them back over HTTPS using an API token.

- The vault is initially closed. Its master key has been divided into 5 Shamir shares, with 5 custodians each holding one share, and any 3 of them being able to unseal the vault.
- All secrets are encrypted with their own data key (AES-256-GCM) and the database contains only the encrypted data.
- Tokens and path policies determine who has access to which secrets for reading or writing.
- All actions are added to an audit log that is hash chained and signed with Ed25519, allowing edits to be detected.
- Client and server communicate via TLS 1.3, and the server uses a certificate from the project's own private CA.

This is a teaching prototype and not production software. See [Limitations](#limitations).

## Contents

- [Requirements](#requirements)
- [Install](#install)
- [Run the tests](#run-the-tests)
- [Run the server](#run-the-server)
- [Use the CLI](#use-the-cli)
- [Demos](#demos)
- [How it works](#how-it-works)
- [Project layout](#project-layout)
- [Limitations](#limitations)
- [Team](#team)
- [Use of AI tools](#use-of-ai-tools)
- [References](#references)

## Requirements

- Python 3.12 or newer
- Git
- On Windows, use the following commands in the Git Bash shell

## Install

Clone the repository and go into it:

```bash
git clone https://github.com/TeamProject-03/vaultlite.git
cd vaultlite
```

Create a virtual environment and install the dependencies.

Windows (Git Bash):

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -r requirements.txt
```

macOS and Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Re-activate the environment (the `source` line) each time a new terminal is opened.

## Run the tests

```bash
python -m pytest
```

Expected result: `118 passed, 1 xfailed`. The expected failure is known to be `test_deleting_the_newest_audit_entry_is_detected`, which is listed in the [Limitations](#limitations).

## Run the server

Generate private CA and server certificate. The files are placed in `certs/` which are ignored by git:

```bash
python scripts/make_ca.py
```

To start the server on port 8200 with TLS:

```bash
python -m uvicorn vaultlite.api.server:app --port 8200 --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt
```

The vault is kept in the current folder in a file called vaultlite.db. Use another file by changing the setting of `VAULTLITE_DB`. Stop the server by hitting Ctrl+C; restarting the server will re-seal the vault as the keys are stored only in memory.

## Use the CLI

Open another terminal and activate the environment and type:

```bash
python -m vaultlite.cli --help
```

| Command | What it does |
|---|---|
| `status` | Indicates if the vault is initialized, sealed or unsealed |
| `init` | Generates the master key and prints out the root token and 5 shares once |
| `unseal` | Submits one of the shares at a hidden prompt; continue until 3 shares are submitted |
| `seal` | Seals the vault and removes the keys from memory (admin token) |
| `put PATH [VALUE]` | Stores a new version of a secret; it queries for a secret at a hidden prompt if VALUE is not provided |
| `get PATH [--version N]` | Reads and decrypts a secret |
| `list` | List secret paths |
| `token create --policy NAME` | Create a token (root, admin, dev-read, dev-write) |
| `rotate master` | New master key and new shares; the old shares stop working |
| `rotate kek` | New vault key: all of the secrets' data keys are re-wrapped |
| `audit-verify` | Verifies hash chain and signatures of audit log |
| `audit-list` | Shows the audit log entries (admin token) |

Options or environment variables can be used to pass settings:

| Option | Environment variable | Default |
|---|---|---|
| `--addr` | `VAULTLITE_ADDR` | `https://localhost:8200` |
| `--ca-cert` | `VAULTLITE_CACERT` | `certs/ca.crt` |
| `--token` | `VAULTLITE_TOKEN` | none |

The CLI validates the certificate that the server provides with certs/ca.crt and rejects TLS versions below 1.3.

### Example session

```bash
alias vl='python -m vaultlite.cli'
vl status
vl init
vl unseal
vl unseal
vl unseal
export VAULTLITE_TOKEN="paste-the-root-token-here"
vl put db/password
vl get db/password
vl token create --policy dev-read
vl audit-verify
vl seal
```

If spaces, $ or ! are part of the value, they need to be in single-quotes: e.g., `vl put db/password 'S3cr3t!'`.

## Demos

### Crypto core demo

Demonstrates the main steps of the flow without the server: initialisation, storage, unsealing with 2 shares, then with 3 shares, incorrect shares, tampering, both rotations. Press the Enter key after every step:

```bash
python scripts/demo_crypto.py --step
```

### Live demonstration with the server

Shares are saved to shares.txt, and not pasted by hand – ignored by git – for presentation. In real use, each share is owned by a different person and is not stored in a single file.

```bash
vl init > shares.txt
share() { grep "Unseal share $1:" shares.txt | awk '{print $4}' | tr -d '\r'; }
share 1 | vl unseal
share 2 | vl unseal
share 3 | vl unseal
export VAULTLITE_TOKEN=$(grep "Root token" shares.txt | awk '{print $3}' | tr -d '\r')
vl put db/password 'S3cr3t-DB-Passw0rd!'
vl put app/api-key abc123
```

In scripts/attack_demo.py the attacker can directly read and write the vaultlite.db file:

```bash
alias attack='python scripts/attack_demo.py'
attack show-db
attack tamper-blob db/password
vl get db/password
attack replay-blob app/api-key db/backup
vl get db/backup
vl get app/api-key
attack edit-audit
vl audit-verify
```

The show-db command will only show the token hashes and the ciphertext. Both of the `get` operations post-attack return 400 and the `audit-verify` operation reports the modified entry.

To reset the whole vault, stop the server, remove the vaultlite.db and shares.txt files, then restart the server.

## How it works

The key hierarchy:

- 5 Shamir shares of the master key (256-bit) over the prime field 2^521 - 1, not stored.
- vault key (KEK): encrypted using a key derived from the master key using HKDF-SHA256; only kept in memory when the vault is unsealed
- **Key-check blob**: allows the server to check for incorrect shares prior to opening the keyring.
- The new key for each secret version (data key, DEK) wrapped by the KEK.
- Secret value encrypted with its DEK with AES-256-GCM, and path and version as associated data, which means that a blob cannot be moved or replayed.
- Ed25519 signing key, wrapped by the KEK: Used to sign each entry in the audit log.

Diagrams:

- System architecture: [`docs/architecture.png`](docs/architecture.png)
- Key hierarchy: [`docs/key_hierarchy.png`](docs/key_hierarchy.png)
- Editable source: [`docs/architecture.drawio`](docs/architecture.drawio)

The threat model, defenses and test evidence are in [`docs/threat_model.md`](docs/threat_model.md).

## Project layout

```text
vaultlite/
  crypto/        shamir, envelope, keyring, rotation, signing, errors
  core/          storage (SQLite), seal state machine, audit log
  api/           FastAPI server, tokens, path policies
  cli.py         command line client
scripts/
  make_ca.py       private CA and server certificate
  demo_crypto.py   crypto core demo
  attack_demo.py   attacker tools for the live demo
tests/           pytest tests, including test_attacks.py
docs/            diagrams and threat model
```

## Limitations

- While the vault is unsealed, the keys are in server memory, and Python can't reliably wipe memory. They can be read by anyone who has control of the running server.
- Each custodian is able to leak their own share, and 3 custodians can open the vault.
- Rotation helps mitigate future exposure, but not past decryption.
- Any events that happen while the vault is sealed are not signable with the vault's signing key.
- Deleting the latest audit entries (or the latest version of a secret) is not detected.
- TLS 1.2 is still supported on the server and there is no limit on the rate of calls to `/v1/unseal`.
- No revoke endpoint and tokens do not expire.

The complete list with recommended remediations is included in [`docs/threat_model.md`](docs/threat_model.md) (gaps G1 - G10).

## Team

| Member | Role | Main parts |
|---|---|---|
| Pranay Paul Reddy | Crypto core | `vaultlite/crypto/`, `scripts/demo_crypto.py` |
| Mohammed Siraj | Server and security | `vaultlite/api/`, `vaultlite/core/`, `scripts/make_ca.py` |
| Amal Mammadzada | Client, testing and documents | `vaultlite/cli.py`, `tests/test_cli.py`, `tests/test_attacks.py`, `scripts/attack_demo.py`, `docs/` |

## Use of AI tools

During this project, AI tools were used for design discussion, drafting and debugging code, as allowed by the guidelines of the unit when declared. The command line client, CLI and attack tests, attack demo script, threat model and diagrams were drafted using AI assistance (Claude, Anthropic); AI assistance was also used to identify and resolve a TLS certificate issue in `scripts/make_ca.py`. The team member responsible for the AI output reviewed, ran and tested all the AI output and can explain it.

## References

- HashiCorp. *Vault documentation*. https://developer.hashicorp.com/vault/docs
- A. Shamir. "How to share a secret." *Communications of the ACM*, 22(11), 612-613, 1979.
- M. Dworkin. Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC. NIST SP 800-38D, 2007.
- H. Krawczyk and P. Eronen. HMAC-based Extract-and-Expand Key Derivation Function (HKDF). RFC 5869, 2010.
- S. Josefsson, I. Liusvaara. Edwards-Curve Digital Signature Algorithm (EdDSA). RFC 8032, 2017.
- E. Rescorla. The Transport Layer Security (TLS) Protocol Version 1.3. RFC 8446, 2018.
- *pyca/cryptography documentation*. https://cryptography.io
- *FastAPI documentation*. https://fastapi.tiangolo.com
- *Click documentation*. https://click.palletsprojects.com
