import sqlite3
import time
from pathlib import Path

import click


def connect(db):
    if not Path(db).exists():
        raise click.ClickException(
            f"database not found: {db}. Run this from the folder where the server was started."
        )
    return sqlite3.connect(db)


def newest_blob(connection, path):
    return connection.execute(
        "SELECT version, blob FROM secrets WHERE path = ? ORDER BY version DESC LIMIT 1", (path,)
    ).fetchone()


def short_hex(data):
    return f"{bytes(data)[:24].hex()}... ({len(data)} bytes)"


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Attacker tools for the live demo. Each command changes vaultlite.db directly, "
    "like someone who has stolen or can write to the database file.",
)
@click.option("--db", envvar="VAULTLITE_DB", default="vaultlite.db", show_default=True,
              help="Path to the vault database.")
@click.pass_context
def cli(ctx, db):
    ctx.obj = db


@cli.command("show-db", help="Show what an attacker sees in the database file.")
@click.pass_obj
def show_db(db):
    connection = connect(db)
    try:
        click.echo("secrets (encrypted blobs):")
        for path, version, blob in connection.execute(
            "SELECT path, version, blob FROM secrets ORDER BY path, version"
        ):
            click.echo(f"  {path} v{version}: {short_hex(blob)}")
        click.echo("tokens (SHA-256 hashes, not the tokens):")
        for token_hash, policy in connection.execute("SELECT token_hash, policy FROM tokens"):
            click.echo(f"  {policy:<10} {token_hash}")
        click.echo("vault_meta (wrapped keys and key-check blob):")
        for key, value in connection.execute("SELECT key, value FROM vault_meta ORDER BY key"):
            click.echo(f"  {key:<14} {short_hex(value)}")
    finally:
        connection.close()


@cli.command("tamper-blob", help="Flip one bit in the newest stored version of the secret at PATH.")
@click.argument("path")
@click.pass_obj
def tamper_blob(db, path):
    connection = connect(db)
    try:
        row = newest_blob(connection, path)
        if row is None:
            raise click.ClickException(f"no secret stored at {path}")
        version, blob = row[0], bytearray(row[1])
        position = len(blob) // 2
        blob[position] ^= 0x01
        connection.execute(
            "UPDATE secrets SET blob = ? WHERE path = ? AND version = ?", (bytes(blob), path, version)
        )
        connection.commit()
    finally:
        connection.close()
    click.echo(f"Flipped one bit in byte {position} of {path} version {version}.")


@cli.command("replay-blob", help="Copy the newest blob of SOURCE and store it as a new version of TARGET.")
@click.argument("source")
@click.argument("target")
@click.pass_obj
def replay_blob(db, source, target):
    connection = connect(db)
    try:
        row = newest_blob(connection, source)
        if row is None:
            raise click.ClickException(f"no secret stored at {source}")
        latest = connection.execute(
            "SELECT MAX(version) FROM secrets WHERE path = ?", (target,)
        ).fetchone()[0]
        version = (latest or 0) + 1
        connection.execute(
            "INSERT INTO secrets (path, version, blob, created_at) VALUES (?, ?, ?, ?)",
            (target, version, row[1], time.time()),
        )
        connection.commit()
    finally:
        connection.close()
    click.echo(f"Copied the blob of {source} version {row[0]} to {target} version {version}.")


@cli.command("edit-audit", help="Change the path in the newest secret.read entry, hiding which secret was read.")
@click.option("--new-path", default="app/harmless", show_default=True, help="Fake path to write.")
@click.pass_obj
def edit_audit(db, new_path):
    connection = connect(db)
    try:
        row = connection.execute(
            "SELECT seq, path FROM audit_log WHERE action = 'secret.read' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise click.ClickException("no secret.read entry in the audit log yet. Read a secret first.")
        connection.execute("UPDATE audit_log SET path = ? WHERE seq = ?", (new_path, row[0]))
        connection.commit()
    finally:
        connection.close()
    click.echo(f"Audit entry {row[0]}: path changed from {row[1]} to {new_path}.")


if __name__ == "__main__":
    cli()
