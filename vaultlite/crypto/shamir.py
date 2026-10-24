"""Shamir's Secret Sharing over a prime field.  OWNER: Student A.

Idea: hide the secret as the constant term of a random polynomial of degree
k-1 over GF(P). A share is a point (x, f(x)) on that polynomial. Any k points
determine the polynomial (Lagrange interpolation), so f(0) = secret can be
rebuilt. Any k-1 points are consistent with every possible secret, so they
reveal nothing (information-theoretic security).
"""
import secrets
from dataclasses import dataclass

from vaultlite.crypto.errors import InvalidSharesError

# 2**521 - 1 is a Mersenne prime, larger than any 64-byte secret we encode.
PRIME = 2**521 - 1
MAX_SECRET_BYTES = 64


@dataclass(frozen=True)
class Share:
    """One Shamir share: the point (index, value) on the secret polynomial."""
    index: int   # x coordinate, 1..n (never 0, because x=0 is the secret)
    value: int   # y coordinate

    def to_str(self) -> str:
        """Serialize for a custodian, e.g. '3-1f9a...' (index-hexvalue)."""
        return f"{self.index}-{self.value:x}"

    @classmethod
    def from_str(cls, text: str) -> "Share":
        """Parse a string produced by to_str()."""
        try:
            idx, val = text.strip().split("-", 1)
            share = cls(int(idx), int(val, 16))
        except ValueError as exc:
            raise InvalidSharesError("malformed share string") from exc
        if not (1 <= share.index <= 255 and 0 <= share.value < PRIME):
            raise InvalidSharesError("share out of range")
        return share


def _encode(secret: bytes) -> int:
    # A leading 0x01 byte preserves leading zero bytes and lets combine()
    # detect garbage (wrong or too few shares) after reconstruction.
    return int.from_bytes(b"\x01" + secret, "big")


def _decode(number: int) -> bytes:
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    if not raw or raw[0] != 1 or len(raw) - 1 > MAX_SECRET_BYTES:
        raise InvalidSharesError(
            "shares did not reconstruct a valid secret (wrong or too few shares)")
    return raw[1:]


def split(secret: bytes, n: int = 5, k: int = 3) -> list[Share]:
    """Split `secret` into `n` shares with threshold `k`.

    Raises ValueError if not 1 < k <= n <= 255, or secret is too long.
    """
    if not (1 < k <= n <= 255):
        raise ValueError("need 1 < k <= n <= 255")
    if len(secret) > MAX_SECRET_BYTES:
        raise ValueError(f"secret longer than {MAX_SECRET_BYTES} bytes")
    # f(x) = secret + c1*x + ... + c(k-1)*x^(k-1); coefficients from the CSPRNG
    coeffs = [_encode(secret)] + [secrets.randbelow(PRIME) for _ in range(k - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        for c in reversed(coeffs):          # Horner's method, mod PRIME
            y = (y * x + c) % PRIME
        shares.append(Share(x, y))
    return shares


def combine(shares: list[Share]) -> bytes:
    """Rebuild the secret from distinct shares via Lagrange interpolation at 0.

    Raises InvalidSharesError for no shares, duplicate indices, or a result
    that is not a valid secret. combine() cannot know k, so fewer than k
    shares usually fail the format check, but the real check is
    keyring.verify_key_check() on the rebuilt master key.
    """
    if not shares:
        raise InvalidSharesError("no shares given")
    indices = [s.index for s in shares]
    if len(set(indices)) != len(indices):
        raise InvalidSharesError("duplicate share indices")
    total = 0
    for i, si in enumerate(shares):
        num, den = 1, 1
        for j, sj in enumerate(shares):
            if i != j:
                num = (num * -sj.index) % PRIME
                den = (den * (si.index - sj.index)) % PRIME
        total = (total + si.value * num * pow(den, -1, PRIME)) % PRIME
    return _decode(total)
