"""Shamir's Secret Sharing over a prime field.  OWNER: Student A.

split()   -> n shares, any k of which rebuild the secret
combine() -> rebuilds the secret from k or more shares
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Share:
    """One Shamir share: the point (index, value) on the secret polynomial."""
    index: int   # x coordinate, 1..n (never 0, because x=0 is the secret)
    value: int   # y coordinate

    def to_str(self) -> str:
        """Serialize for handing to a custodian (e.g. '1-ab12...')."""
        raise NotImplementedError("A: implement Share.to_str")

    @classmethod
    def from_str(cls, text: str) -> "Share":
        """Parse a string produced by to_str()."""
        raise NotImplementedError("A: implement Share.from_str")


def split(secret: bytes, n: int = 5, k: int = 3) -> list[Share]:
    """Split `secret` into `n` shares with threshold `k`.

    Raises ValueError if not 1 < k <= n.
    """
    raise NotImplementedError("A: implement split")


def combine(shares: list[Share]) -> bytes:
    """Rebuild the secret from at least k distinct shares.

    Raises InvalidSharesError for duplicates or too few shares.
    NOTE: combine() cannot tell if shares are correct. Use
    keyring.verify_key_check() on the result to detect wrong shares.
    """
    raise NotImplementedError("A: implement combine")



