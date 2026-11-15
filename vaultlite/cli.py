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

HINTS = {
    401: "Check your token (set VAULTLITE_TOKEN or pass --token).",
    403: "This token's policy does not allow that action on that path.",
    503: "The vault is sealed. Run 'unseal' with enough shares first.",
}


def make_tls_context(ca_cert: str) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_cert)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def get_client(ctx: click.Context) -> httpx.Client:
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
    clean = path.strip().strip("/")
    if not clean:
        raise click.ClickException("the secret path must not be empty, for example db/password")
    return "/v1/secret/" + quote(clean, safe="/")


def read_quorum(ctx: click.Context, count: Optional[int]) -> list[str]:
    if count is None:
        count = call(ctx, "GET", "/v1/status")["threshold"]
    return [read_secret(f"Current unseal share {i} of {count}") for i in range(1, count + 1)]


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help="VaultLite: a small Vault-style secrets manager (command line client).",
)
@click.option("--addr", envvar="VAULTLITE_ADDR", default=DEFAULT_ADDR, show_default=True,
              help="Server address. Env: VAULTLITE_ADDR")
@click.option("--ca-cert", envvar="VAULTLITE_CACERT", default=DEFAULT_CA_CERT, show_default=True,
              help="CA certificate that signed the server certificate. Env: VAULTLITE_CACERT")
@click.option("--token", envvar="VAULTLITE_TOKEN", default=None,
              help="API token. Env: VAULTLITE_TOKEN")
@click.pass_context
def cli(ctx: click.Context, addr: str, ca_cert: str, token: Optional[str]) -> None:
    ctx.ensure_object(dict)
    ctx.obj.update(addr=addr.rstrip("/"), ca_cert=ca_cert, token=token)


@cli.command(help="Show whether the vault is initialized, sealed or unsealed.")
@click.pass_context
def status(ctx: click.Context) -> None:
    data = call(ctx, "GET", "/v1/status")
    click.echo(f"Initialized : {'yes' if data['initialized'] else 'no'}")
    click.echo(f"State       : {data['state']}")
    if data["initialized"]:
        click.echo(f"Unseal rule : any {data['threshold']} of {data['shares_count']} shares")
        if data["state"] in ("sealed", "unsealing"):
            click.echo(f"Progress    : {data['shares_collected']} of {data['threshold']} shares submitted")


@cli.command(help="Initialize a new vault: create the master key and split it into shares.")
@click.option("--shares", "-n", default=5, show_default=True, help="Number of shares to create.")
@click.option("--threshold", "-k", default=3, show_default=True, help="Shares needed to unseal.")
@click.pass_context
def init(ctx: click.Context, shares: int, threshold: int) -> None:
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


@cli.command(help="Submit ONE unseal share. Repeat until the vault is unsealed.")
@click.pass_context
def unseal(ctx: click.Context) -> None:
    share = read_secret("Unseal share")
    data = call(ctx, "POST", "/v1/unseal", json_body={"share": share})
    if data["state"] == "unsealed":
        click.echo("Vault is UNSEALED.")
    else:
        click.echo(f"Share accepted. Vault is still SEALED: {data['shares_needed']} more share(s) needed.")


@cli.command(help="Seal the vault now: the server forgets its keys (admin token).")
@click.pass_context
def seal(ctx: click.Context) -> None:
    data = call(ctx, "POST", "/v1/seal", auth=True)
    click.echo(data.get("message", "vault is sealed"))


@cli.command(help="Store a secret at PATH. Each put creates a new version. Leave out VALUE "
                  "to type it at a hidden prompt, which keeps it out of the shell history.")
@click.argument("path")
@click.argument("value", required=False)
@click.pass_context
def put(ctx: click.Context, path: str, value: Optional[str]) -> None:
    url = secret_url(path)
    if value is None:
        value = read_secret(f"Value for {path}")
    data = call(ctx, "PUT", url, json_body={"value": value}, auth=True)
    click.echo(f"Stored {data['path']} (version {data['version']}).")


@cli.command(help="Read and decrypt the secret at PATH (latest version by default).")
@click.argument("path")
@click.option("--version", "version", type=int, default=None, help="Read an older version.")
@click.pass_context
def get(ctx: click.Context, path: str, version: Optional[int]) -> None:
    params = {"version": version} if version is not None else None
    data = call(ctx, "GET", secret_url(path), params=params, auth=True)
    click.echo(f"Path    : {data['path']}")
    click.echo(f"Version : {data['version']}")
    click.echo(f"Value   : {data['value']}")


@cli.command("list", help="List the paths of all stored secrets.")
@click.pass_context
def list_secrets(ctx: click.Context) -> None:
    paths = call(ctx, "GET", "/v1/secrets", auth=True)["secrets"]
    if not paths:
        click.echo("(no secrets stored)")
    for path in paths:
        click.echo(path)


@cli.group(help="Manage API tokens (needs an admin or root token).")
def token() -> None:
    pass


@token.command("create", help="Create a new API token with the given policy.")
@click.option("--policy", default="dev-read", show_default=True,
              help="Built-in policies: root, admin, dev-read, dev-write.")
@click.option("--description", default="", help="Note saying who the token is for.")
@click.pass_context
def token_create(ctx: click.Context, policy: str, description: str) -> None:
    data = call(ctx, "POST", "/v1/tokens",
                json_body={"policy": policy, "description": description}, auth=True)
    click.echo(f"New token ({data['policy']}): {data['token']}")
    click.echo("Shown only once. The server stores only its SHA-256 hash.")


@cli.group(help="Rotate keys (needs an admin token and a quorum of current shares).")
def rotate() -> None:
    pass


@rotate.command("master", help="Make a new master key and new shares. The old shares stop working.")
@click.option("--count", type=int, default=None,
              help="How many shares to enter (default: the vault's threshold).")
@click.pass_context
def rotate_master(ctx: click.Context, count: Optional[int]) -> None:
    shares = read_quorum(ctx, count)
    data = call(ctx, "POST", "/v1/rotate/master", json_body={"shares": shares}, auth=True)
    click.echo("Master key rotated. The OLD shares no longer work.\n")
    for number, share in enumerate(data["new_shares"], start=1):
        click.echo(f"New unseal share {number}: {share}")
    click.echo("\nThese new shares are shown ONLY ONCE. Hand them out again.")


@rotate.command("kek", help="Make a new vault key (KEK) and re-wrap every secret's data key.")
@click.option("--count", type=int, default=None,
              help="How many shares to enter (default: the vault's threshold).")
@click.pass_context
def rotate_kek(ctx: click.Context, count: Optional[int]) -> None:
    shares = read_quorum(ctx, count)
    data = call(ctx, "POST", "/v1/rotate/kek", json_body={"shares": shares}, auth=True)
    click.echo(data.get("message", "KEK rotated."))


@cli.command("audit-verify", help="Check the audit log's hash chain and Ed25519 signatures. "
                                  "Exits with code 1 if the log was edited.")
@click.pass_context
def audit_verify(ctx: click.Context) -> None:
    data = call(ctx, "GET", "/v1/audit/verify")
    if data["valid"]:
        click.echo("Audit log OK: every hash link and signature verified.")
    else:
        raise click.ClickException(f"AUDIT LOG TAMPERED: {data['error']}")


@cli.command("audit-list", help="Show the audit log entries (needs an admin or root token).")
@click.pass_context
def audit_list(ctx: click.Context) -> None:
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
