import vaultlite.crypto.shamir as shamir
import vaultlite.crypto.envelope as envelope
import vaultlite.crypto.keyring as keyring
import vaultlite.crypto.rotation as rotation


def test_interface_exists():
    for fn in (shamir.split, shamir.combine,
               envelope.generate_master_key, envelope.encrypt_secret,
               envelope.decrypt_secret,
               keyring.make_keyring, keyring.open_keyring,
               keyring.make_key_check, keyring.verify_key_check,
               rotation.rotate_master_key, rotation.rewrap_secret):
        assert callable(fn)
