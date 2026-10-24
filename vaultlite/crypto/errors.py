"""Exceptions raised by the crypto core. B (server) should catch these."""


class VaultCryptoError(Exception):
    """Base class for all crypto-core errors."""


class InvalidSharesError(VaultCryptoError):
    """Not enough shares, duplicate shares, or malformed shares."""


class WrongMasterKeyError(VaultCryptoError):
    """Combined shares did not produce the correct master key (key-check failed)."""


class DecryptionError(VaultCryptoError):
    """Ciphertext was tampered with, or the key/path/version is wrong."""
