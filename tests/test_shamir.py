import itertools
import secrets

import pytest

from vaultlite.crypto.errors import InvalidSharesError
from vaultlite.crypto.shamir import Share, combine, split


def test_any_3_of_5_rebuild_secret():
    secret = secrets.token_bytes(32)
    shares = split(secret, n=5, k=3)
    for combo in itertools.combinations(shares, 3):
        assert combine(list(combo)) == secret


def test_more_than_threshold_also_works():
    secret = secrets.token_bytes(32)
    shares = split(secret, 5, 3)
    assert combine(shares) == secret
    assert combine(shares[:4]) == secret


def test_share_order_does_not_matter():
    secret = secrets.token_bytes(32)
    shares = split(secret, 5, 3)
    assert combine([shares[4], shares[0], shares[2]]) == secret


def test_two_shares_do_not_reveal_secret():
    secret = secrets.token_bytes(32)
    shares = split(secret, 5, 3)
    for combo in itertools.combinations(shares, 2):
        try:
            assert combine(list(combo)) != secret
        except InvalidSharesError:
            pass  # rejected as invalid: also fine


def test_duplicate_shares_rejected():
    shares = split(b"secret", 5, 3)
    with pytest.raises(InvalidSharesError):
        combine([shares[0], shares[0], shares[1]])


def test_no_shares_rejected():
    with pytest.raises(InvalidSharesError):
        combine([])


def test_leading_zero_bytes_preserved():
    secret = b"\x00\x00abc\x00"
    assert combine(split(secret, 5, 3)[:3]) == secret


def test_empty_secret_roundtrip():
    assert combine(split(b"", 5, 3)[:3]) == b""


def test_bad_parameters():
    with pytest.raises(ValueError):
        split(b"x", n=5, k=1)
    with pytest.raises(ValueError):
        split(b"x", n=2, k=3)
    with pytest.raises(ValueError):
        split(b"x" * 65, 5, 3)


def test_shares_are_random_each_time():
    a = split(b"same secret", 5, 3)
    b = split(b"same secret", 5, 3)
    assert a != b


def test_share_string_roundtrip():
    secret = secrets.token_bytes(32)
    shares = split(secret, 5, 3)
    restored = [Share.from_str(s.to_str()) for s in shares[:3]]
    assert combine(restored) == secret


def test_malformed_share_string():
    for bad in ("", "abc", "0-ff", "1-zz", "999-ff"):
        with pytest.raises(InvalidSharesError):
            Share.from_str(bad)
