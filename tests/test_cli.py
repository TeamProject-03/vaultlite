import re

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from vaultlite.api.server import create_app
from vaultlite.cli import cli
from vaultlite.core.storage import Storage

SHARE_RE = re.compile(r"Unseal share \d+: (\S+)")
NEW_SHARE_RE = re.compile(r"New unseal share \d+: (\S+)")
ROOT_TOKEN_RE = re.compile(r"Root token: (\S+)")


@pytest.fixture
def vault():
    storage = Storage(":memory:")
    with TestClient(create_app(storage=storage)) as http:
        yield http
    storage.close()


def run(http, args, token=None, input=None):
    return CliRunner().invoke(
        cli, args, obj={"client": http}, env={"VAULTLITE_TOKEN": token}, input=input
    )


def init_vault(http):
    result = run(http, ["init"])
    assert result.exit_code == 0, result.output
    return SHARE_RE.findall(result.output), ROOT_TOKEN_RE.search(result.output).group(1)


def unseal_with(http, shares):
    result = None
    for share in shares:
        result = run(http, ["unseal"], input=share + "\n")
    return result


def test_status_before_init(vault):
    result = run(vault, ["status"])
    assert result.exit_code == 0
    assert "uninitialized" in result.output


def test_init_prints_five_shares_and_a_root_token(vault):
    shares, root_token = init_vault(vault)
    assert len(shares) == 5
    assert root_token.startswith("s.vaultlite_")
    assert "sealed" in run(vault, ["status"]).output


def test_unseal_needs_three_shares(vault):
    shares, _ = init_vault(vault)
    first = unseal_with(vault, shares[:1])
    assert "2 more share(s) needed" in first.output
    second = unseal_with(vault, shares[1:2])
    assert "1 more share(s) needed" in second.output
    third = unseal_with(vault, shares[2:3])
    assert "UNSEALED" in third.output
    assert "State       : unsealed" in run(vault, ["status"]).output


def test_put_and_get_with_versions(vault):
    shares, root_token = init_vault(vault)
    unseal_with(vault, shares[:3])

    result = run(vault, ["put", "db/password", "S3cr3t!"], token=root_token)
    assert result.exit_code == 0, result.output
    assert "version 1" in result.output

    result = run(vault, ["put", "db/password"], token=root_token, input="second-value\n")
    assert "version 2" in result.output

    latest = run(vault, ["get", "db/password"], token=root_token)
    assert "second-value" in latest.output
    old = run(vault, ["get", "db/password", "--version", "1"], token=root_token)
    assert "S3cr3t!" in old.output
    assert "db/password" in run(vault, ["list"], token=root_token).output


def test_secret_commands_fail_while_sealed(vault):
    _, root_token = init_vault(vault)
    result = run(vault, ["get", "db/password"], token=root_token)
    assert result.exit_code == 1
    assert "HTTP 503" in result.output
    assert "unseal" in result.output


def test_missing_token_gives_a_clear_message(vault):
    shares, _ = init_vault(vault)
    unseal_with(vault, shares[:3])
    result = run(vault, ["get", "db/password"])
    assert result.exit_code == 1
    assert "needs a token" in result.output


def test_wrong_token_is_rejected(vault):
    shares, _ = init_vault(vault)
    unseal_with(vault, shares[:3])
    result = run(vault, ["get", "db/password"], token="s.vaultlite_" + "0" * 64)
    assert result.exit_code == 1
    assert "HTTP 401" in result.output


def test_read_only_token_cannot_write(vault):
    shares, root_token = init_vault(vault)
    unseal_with(vault, shares[:3])
    created = run(vault, ["token", "create", "--policy", "dev-read"], token=root_token)
    read_only = re.search(r"New token \(dev-read\): (\S+)", created.output).group(1)

    result = run(vault, ["put", "db/password", "hacked"], token=read_only)
    assert result.exit_code == 1
    assert "HTTP 403" in result.output


def test_rotate_master_gives_new_shares_and_old_ones_stop_working(vault):
    shares, root_token = init_vault(vault)
    unseal_with(vault, shares[:3])
    run(vault, ["put", "db/password", "keep-me"], token=root_token)

    result = run(vault, ["rotate", "master"], token=root_token, input="\n".join(shares[:3]) + "\n")
    assert result.exit_code == 0, result.output
    new_shares = NEW_SHARE_RE.findall(result.output)
    assert len(new_shares) == 5

    assert run(vault, ["seal"], token=root_token).exit_code == 0
    old = unseal_with(vault, shares[:3])
    assert old.exit_code == 1
    assert "HTTP 400" in old.output

    assert "UNSEALED" in unseal_with(vault, new_shares[:3]).output
    assert "keep-me" in run(vault, ["get", "db/password"], token=root_token).output


def test_rotate_kek_keeps_secrets_readable(vault):
    shares, root_token = init_vault(vault)
    unseal_with(vault, shares[:3])
    run(vault, ["put", "app/api-key", "abc123"], token=root_token)

    result = run(vault, ["rotate", "kek"], token=root_token, input="\n".join(shares[:3]) + "\n")
    assert result.exit_code == 0, result.output
    assert "abc123" in run(vault, ["get", "app/api-key"], token=root_token).output


def test_audit_verify_and_list(vault):
    shares, root_token = init_vault(vault)
    unseal_with(vault, shares[:3])
    run(vault, ["put", "db/password", "x"], token=root_token)

    verify = run(vault, ["audit-verify"])
    assert verify.exit_code == 0
    assert "Audit log OK" in verify.output
    listing = run(vault, ["audit-list"], token=root_token)
    assert "secret.write" in listing.output


def test_missing_ca_certificate_is_reported(tmp_path):
    result = CliRunner().invoke(cli, ["--ca-cert", str(tmp_path / "missing.crt"), "status"])
    assert result.exit_code == 1
    assert "CA certificate not found" in result.output
