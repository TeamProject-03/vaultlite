"""VaultLite command line client.  OWNER: Amal Mammadzada (Student C).

The CLI talks to the VaultLite server over HTTPS. Every command is a thin
wrapper around one REST endpoint in vaultlite/api/server.py, so the CLI
never touches keys, the database or the crypto core itself.

Run it from the project folder with the virtual environment active:

    python -m vaultlite.cli status
    python -m vaultlite.cli init
    python -m vaultlite.cli unseal              (once per share, 3 times)
    python -m vaultlite.cli put db/password     (value asked at a hidden prompt)
    python -m vaultlite.cli get db/password
    python -m vaultlite.cli rotate master
    python -m vaultlite.cli audit-verify

Settings (command line option, or environment variable):

    --addr     VAULTLITE_ADDR     server address (default https://localhost:8200)
    --ca-cert  VAULTLITE_CACERT   our private CA certificate (default certs/ca.crt)
    --token    VAULTLITE_TOKEN    API token for commands that need one

Security choices:
- The server's certificate is always checked against our private CA, and
  the client refuses any TLS version older than 1.3.
- Shares, secret values and tokens are typed at a hidden prompt or piped in,
  so they never end up in the shell history.
- The token is sent only to endpoints that need it, in the X-Vault-Token
  header.
- Shares and tokens are printed once (init, token create, rotate master).
  The client never writes anything to disk.
"""
import ssl
import sys
from datetime import datetime
from typing import Any, Optional
from urllib.parse import quote

import click
import httpx

DEFAULT_ADDR = "https://localhost:8200"
DEFAULT_CA_CERT = "certs/ca.crt"
TIMEOUT_SECONDS = 10.0

# Extra advice printed under an error, by HTTP status code.
HINTS = {
    401: "Check your token (set VAULTLITE_TOKEN or pass --token).",
    403: "This token's policy does not allow that action on that path.",
    503: "The vault is sealed. Run 'unseal' with enough shares first.",
}


# ------------------------------------------------------------------ helpers
def make_tls_context(ca_cert: str) -> ssl.SSLContext:
    """Trust only our private CA, check the host name, and require TLS 1.3."""
    context = ssl.create_default_context(cafile=ca_cert)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def get_client(ctx: click.Context) -> httpx.Client:
    """Return the HTTP client, creating it on first use.

    Tests put a FastAPI TestClient in ctx.obj["client"] instead, so the same
    commands can run without a network or certificates.
    """
    state = ctx.obj
    if state.get("client") is None:
        ca_cert = state["ca_cert"]
        try:
            tls = make_tls_context(ca_cert)
        except FileNotFoundError:
            raise click.ClickException(
                f"CA certificate not found: {ca_cert}\n"
                "Run 'python scripts/make_ca.py' first, or pass --ca-cert."
            )
        except ssl.SSLError as exc:
            raise click.ClickException(f"could not load CA certificate {ca_cert}: {exc}")
        client = httpx.Client(base_url=state["addr"], verify=tls, timeout=TIMEOUT_SECONDS)
        state["client"] = client
        ctx.find_root().call_on_close(client.close)
    return state["client"]


def call(
    ctx: click.Context,
    method: str,
    url: str,
    json_body: Optional[dict[str, Any]] = None,
    params: Optional[dict[str, Any]] = None,
    auth: bool = False,
) -> dict[str, Any]:
    """Send one request to the server and return the JSON answer.

    Any error (server down, bad certificate, HTTP 4xx/5xx) becomes a short
    message and exit code 1, never a Python traceback.
    """
    headers = {}
    if auth:
        token = ctx.obj.get("token")
        if not token:
            raise click.ClickException(
                "this command needs a token. Set VAULTLITE_TOKEN or pass --token."
            )
        headers["X-Vault-Token"] = token

    client = get_client(ctx)
    try:
        response = client.request(method, url, json=json_body, params=params, headers=headers)
    except httpx.ConnectError as exc:
        if "SSL" in str(exc) or "CERTIFICATE" in str(exc).upper():
            raise click.ClickException(
                f"TLS check failed for {ctx.obj['addr']}: the server certificate is not "
                "signed by our CA, or the server does not offer TLS 1.3."
            )
        raise click.ClickException(
            f"cannot reach the server at {ctx.obj['addr']}. Is it running?"
        )
    except httpx.TimeoutException:
        raise click.ClickException(f"the server at {ctx.obj['addr']} did not answer in time.")

    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        message = f"HTTP {response.status_code}: {detail}"
        if response.status_code in HINTS:
            message += "\n" + HINTS[response.status_code]
        raise click.ClickException(message)

    return response.json()


def read_secret(label: str) -> str:
    """Read a share, token or secret value without echoing it.

    In a real terminal the input is hidden. Without one (piped input, tests,
    or the mintty window of Git Bash on Windows, where hidden input does not
    work) one line is read from standard input instead.
    """
    if sys.stdin.isatty():
        value = click.prompt(label, hide_input=True)
    else:
        click.echo(f"{label} (input is visible in this terminal): ", nl=False, err=True)
        value = sys.stdin.readline()
        click.echo("", err=True)
    value = value.strip()
    if not value:
        raise click.ClickException(f"{label} must not be empty.")
    return value


def secret_url(path: str) -> str:
    """Build /v1/secret/<path>, rejecting an empty path."""
    clean = path.strip().strip("/")
    if not clean:
        raise click.ClickException("the secret path must not be empty, for example db/password")
    return "/v1/secret/" + quote(clean, safe="/")


def read_quorum(ctx: click.Context, count: Optional[int]) -> list[str]:
    """Ask for enough current shares to authorise a rotation."""
    if count is None:
        count = call(ctx, "GET", "/v1/status")["threshold"]
    return [read_secret(f"Current unseal share {i} of {count}") for i in range(1, count + 1)]


# ----------------------------------------------------------------- commands
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--addr", envvar="VAULTLITE_ADDR", default=DEFAULT_ADDR, show_default=True,
              help="Server address. Env: VAULTLITE_ADDR")
@click.option("--ca-cert", envvar="VAULTLITE_CACERT", default=DEFAULT_CA_CERT, show_default=True,
              help="CA certificate that signed the server certificate. Env: VAULTLITE_CACERT")
@click.option("--token", envvar="VAULTLITE_TOKEN", default=None,
              help="API token. Env: VAULTLITE_TOKEN")
@click.pass_context
def cli(ctx: click.Context, addr: str, ca_cert: str, token: Optional[str]) -> None:
    """VaultLite: a small Vault-style secrets manager (command line client)."""
    ctx.ensure_object(dict)
    ctx.obj.update(addr=addr.rstrip("/"), ca_cert=ca_cert, token=token)


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show whether the vault is initialized, sealed or unsealed."""
    data = call(ctx, "GET", "/v1/status")
    click.echo(f"Initialized : {'yes' if data['initialized'] else 'no'}")
    click.echo(f"State       : {data['state']}")
    if data["initialized"]:
        click.echo(f"Unseal rule : any {data['threshold']} of {data['shares_count']} shares")
        if data["state"] in ("sealed", "unsealing"):
            click.echo(f"Progress    : {data['shares_collected']} of {data['threshold']} shares submitted")


@cli.command()
@click.option("--shares", "-n", default=5, show_default=True, help="Number of shares to create.")
@click.option("--threshold", "-k", default=3, show_default=True, help="Shares needed to unseal.")
@click.pass_context
def init(ctx: click.Context, shares: int, threshold: int) -> None:
    """Initialize a new vault: create the master key and split it into shares."""
    data = call(ctx, "POST", "/v1/init", json_body={"shares": shares, "threshold": threshold})
    click.echo(f"Vault initialized. It stays SEALED until {threshold} shares are submitted.\n")
    for number, share in enumerate(data["shares"], start=1):
        click.echo(f"Unseal share {number}: {share}")
    if data.get("root_token"):
        click.echo(f"\nRoot token: {data['root_token']}")
    click.echo(
        "\nThese values are shown ONLY ONCE. Give each share to a different person,"
        "\nkeep the root token safe, and never commit any of them to Git."
    )


@cli.command()
@click.pass_context
def unseal(ctx: click.Context) -> None:
    """Submit ONE unseal share. Repeat until the vault is unsealed."""
    share = read_secret("Unseal share")
    data = call(ctx, "POST", "/v1/unseal", json_body={"share": share})
    if data["state"] == "unsealed":
        click.echo("Vault is UNSEALED.")
    else:
        click.echo(f"Share accepted. Vault is still SEALED: {data['shares_needed']} more share(s) needed.")


@cli.command()
@click.pass_context
def seal(ctx: click.Context) -> None:
    """Seal the vault now: the server forgets its keys (admin token)."""
    data = call(ctx, "POST", "/v1/seal", auth=True)
    click.echo(data.get("message", "vault is sealed"))


@cli.command()
@click.argument("path")
@click.argument("value", required=False)
@click.pass_context
def put(ctx: click.Context, path: str, value: Optional[str]) -> None:
    """Store a secret at PATH. Each put creates a new version.

    Leave out VALUE to type it at a hidden prompt, which keeps it out of the
    shell history.
    """
    url = secret_url(path)
    if value is None:
        value = read_secret(f"Value for {path}")
    data = call(ctx, "PUT", url, json_body={"value": value}, auth=True)
    click.echo(f"Stored {data['path']} (version {data['version']}).")


@cli.command()
@click.argument("path")
@click.option("--version", "version", type=int, default=None, help="Read an older version.")
@click.pass_context
def get(ctx: click.Context, path: str, version: Optional[int]) -> None:
    """Read and decrypt the secret at PATH (latest version by default)."""
    params = {"version": version} if version is not None else None
    data = call(ctx, "GET", secret_url(path), params=params, auth=True)
    click.echo(f"Path    : {data['path']}")
    click.echo(f"Version : {data['version']}")
    click.echo(f"Value   : {data['value']}")


@cli.command("list")
@click.pass_context
def list_secrets(ctx: click.Context) -> None:
    """List the paths of all stored secrets."""
    paths = call(ctx, "GET", "/v1/secrets", auth=True)["secrets"]
    if not paths:
        click.echo("(no secrets stored)")
    for path in paths:
        click.echo(path)


@cli.group()
def token() -> None:
    """Manage API tokens (needs an admin or root token)."""


@token.command("create")
@click.option("--policy", default="dev-read", show_default=True,
              help="Built-in policies: root, admin, dev-read, dev-write.")
@click.option("--description", default="", help="Note saying who the token is for.")
@click.pass_context
def token_create(ctx: click.Context, policy: str, description: str) -> None:
    """Create a new API token with the given policy."""
    data = call(ctx, "POST", "/v1/tokens",
                json_body={"policy": policy, "description": description}, auth=True)
    click.echo(f"New token ({data['policy']}): {data['token']}")
    click.echo("Shown only once. The server stores only its SHA-256 hash.")


@cli.group()
def rotate() -> None:
    """Rotate keys (needs an admin token and a quorum of current shares)."""


@rotate.command("master")
@click.option("--count", type=int, default=None,
              help="How many shares to enter (default: the vault's threshold).")
@click.pass_context
def rotate_master(ctx: click.Context, count: Optional[int]) -> None:
    """Make a new master key and new shares. The old shares stop working."""
    shares = read_quorum(ctx, count)
    data = call(ctx, "POST", "/v1/rotate/master", json_body={"shares": shares}, auth=True)
    click.echo("Master key rotated. The OLD shares no longer work.\n")
    for number, share in enumerate(data["new_shares"], start=1):
        click.echo(f"New unseal share {number}: {share}")
    click.echo("\nThese new shares are shown ONLY ONCE. Hand them out again.")


@rotate.command("kek")
@click.option("--count", type=int, default=None,
              help="How many shares to enter (default: the vault's threshold).")
@click.pass_context
def rotate_kek(ctx: click.Context, count: Optional[int]) -> None:
    """Make a new vault key (KEK) and re-wrap every secret's data key."""
    shares = read_quorum(ctx, count)
    data = call(ctx, "POST", "/v1/rotate/kek", json_body={"shares": shares}, auth=True)
    click.echo(data.get("message", "KEK rotated."))


@cli.command("audit-verify")
@click.pass_context
def audit_verify(ctx: click.Context) -> None:
    """Check the audit log's hash chain and Ed25519 signatures.

    Exits with code 1 if the log was edited. Note: removing the newest
    entries is not detected, because nothing records where the chain ends.
    """
    data = call(ctx, "GET", "/v1/audit/verify")
    if data["valid"]:
        click.echo("Audit log OK: every hash link and signature verified.")
    else:
        raise click.ClickException(f"AUDIT LOG TAMPERED: {data['error']}")


@cli.command("audit-list")
@click.pass_context
def audit_list(ctx: click.Context) -> None:
    """Show the audit log entries (needs an admin or root token)."""
    entries = call(ctx, "GET", "/v1/audit/entries", auth=True)["entries"]
    if not entries:
        click.echo("(audit log is empty)")
    for entry in entries:
        when = datetime.fromtimestamp(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        signed = "unsigned" if entry["signature"] == "UNSIGNED_VAULT_SEALED" else "signed"
        click.echo(
            f"{entry['seq']:>4}  {when}  {entry['status']}  {entry['action']:<22} "
            f"{entry['path'] or '-':<16} {entry['actor']:<16} {signed}"
        )


if __name__ == "__main__":
    cli()
