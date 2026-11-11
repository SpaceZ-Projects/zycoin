"""In-memory transparent and Sapling key derivation with encrypted records."""

from .crypto import public_key_to_p2pkh, pw_decode, pw_encode, xpub_from_xprv
from .coins import get_coin_network
from .keystore import (
    BIP32_KeyStore,
    bip44_derivation,
    xtype_from_derivation,
)
from .mnemonic import mnemonic_to_seed
from .addresses import SaplingCapabilityError, get_network
from .derivation import ExtendedSpendingKey


class TransparentWallet:
    """A BIP44 account derived in memory for one configured coin network."""

    RECORD_VERSION = 1

    def __init__(self, keystore, account):
        self._keystore = keystore
        self.account = account
        self.network = keystore.network

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic,
        coin,
        network="mainnet",
        passphrase="",
        account=0,
    ):
        derivation = bip44_derivation(account, coin, network)
        network_config = get_coin_network(coin, network)
        keystore = BIP32_KeyStore({
            "coin_id": network_config.coin_id,
            "network_id": network_config.network_id,
        })
        keystore.add_xprv_from_seed(
            mnemonic_to_seed(mnemonic, passphrase),
            xtype_from_derivation(derivation),
            derivation,
        )
        return cls(keystore, account)

    @classmethod
    def from_record(cls, record, password):
        if not isinstance(password, str) or not password:
            raise ValueError("a non-empty wallet password is required")
        if not isinstance(record, dict) or record.get("version") != cls.RECORD_VERSION:
            raise ValueError("unsupported transparent wallet record")
        coin_id = record.get("coin_id")
        network_id = record.get("network_id")
        account = record.get("account")
        network_config = get_coin_network(coin_id, network_id)
        bip44_derivation(account, coin_id, network_id)
        encrypted = record.get("encrypted_xprv")
        expected_xpub = record.get("xpub")
        if not isinstance(encrypted, str) or not isinstance(expected_xpub, str):
            raise ValueError("transparent wallet record is missing key material")
        try:
            xprv = pw_decode(encrypted, password)
            actual_xpub = xpub_from_xprv(xprv, net=network_config)
        except Exception as exc:
            raise ValueError(
                "could not decrypt or decode transparent wallet record"
            ) from exc
        if actual_xpub != expected_xpub:
            raise ValueError("transparent wallet record key does not match its public key")
        keystore = BIP32_KeyStore({
            "coin_id": network_config.coin_id,
            "network_id": network_config.network_id,
        })
        keystore.xprv = xprv
        keystore.xpub = actual_xpub
        return cls(keystore, account)

    def derive_public_key(self, index=0, change=0):
        _validate_address_index(index, "index")
        _validate_address_index(change, "change")
        if change not in (0, 1):
            raise ValueError("change must be 0 (receive) or 1 (change)")
        return bytes.fromhex(self._keystore.derive_pubkey(change, index))

    def derive_private_key(self, index=0, change=0):
        _validate_address_index(index, "index")
        _validate_address_index(change, "change")
        if change not in (0, 1):
            raise ValueError("change must be 0 (receive) or 1 (change)")
        private_key, _ = self._keystore.get_private_key([change, index], None)
        return private_key

    def address(self, index=0, change=0):
        return public_key_to_p2pkh(
            self.derive_public_key(index=index, change=change),
            self.network,
        )

    def to_record(self, password):
        if not isinstance(password, str) or not password:
            raise ValueError("a non-empty wallet password is required")
        return {
            "version": self.RECORD_VERSION,
            "coin_id": self.network.coin_id,
            "network_id": self.network.network_id,
            "account": self.account,
            "xpub": self._keystore.xpub,
            "encrypted_xprv": pw_encode(self._keystore.xprv, password),
        }


def _validate_address_index(index, name):
    if (
        isinstance(index, bool)
        or not isinstance(index, int)
        or not 0 <= index < (1 << 31)
    ):
        raise ValueError(f"{name} must be in [0, 2^31)")


class SaplingWallet:
    """A ZIP32 wallet root; key derivation is available, but spending is not."""

    RECORD_VERSION = 1

    def __init__(self, spending_key, network):
        if not isinstance(spending_key, ExtendedSpendingKey):
            raise TypeError("spending_key must be an ExtendedSpendingKey")
        if not getattr(network, "wallet_derivation_supported", False):
            raise SaplingCapabilityError(
                f"Sapling wallet derivation is not verified for "
                f"{getattr(network, 'name', 'unknown network')}"
            )
        self._spending_key = spending_key
        self.network = network

    @classmethod
    def from_mnemonic(cls, mnemonic, network="zec-mainnet", passphrase=""):
        coin_network = get_network(network)
        if not coin_network.wallet_derivation_supported:
            raise SaplingCapabilityError(
                f"Sapling wallet derivation is not verified for {coin_network.name}"
            )
        root = ExtendedSpendingKey.master(mnemonic_to_seed(mnemonic, passphrase))
        return cls(root, coin_network)

    @classmethod
    def from_record(cls, record, password):
        if not isinstance(password, str) or not password:
            raise ValueError("a non-empty wallet password is required")
        if not isinstance(record, dict) or record.get("version") != cls.RECORD_VERSION:
            raise ValueError("unsupported Sapling wallet record")
        network = get_network(record.get("network"))
        if not network.wallet_derivation_supported:
            raise SaplingCapabilityError(
                f"Sapling wallet derivation is not verified for {network.name}"
            )
        encrypted = record.get("encrypted_xsk")
        if not isinstance(encrypted, str):
            raise ValueError("Sapling wallet record has no encrypted spending key")
        try:
            spending_key = ExtendedSpendingKey.deserialize(
                bytes.fromhex(pw_decode(encrypted, password))
            )
        except Exception as exc:
            raise ValueError("could not decrypt or decode Sapling wallet record") from exc
        return cls(spending_key, network)

    restore = from_record

    def to_record(self, password):
        if not isinstance(password, str) or not password:
            raise ValueError("a non-empty wallet password is required")
        return {
            "version": self.RECORD_VERSION,
            "network": self.network.name,
            "encrypted_xsk": pw_encode(self._spending_key.serialize().hex(), password),
        }

    def derive_spending_key(self, path=None, account=0):
        if path is None:
            if (
                isinstance(account, bool)
                or not isinstance(account, int)
                or not 0 <= account < (1 << 31)
            ):
                raise ValueError("ZIP32 account index must be in [0, 2^31)")
            template = self.network.default_derivation_path
            if not template:
                raise SaplingCapabilityError(
                    f"no verified ZIP32 account path is configured for {self.network.name}"
                )
            derivation_path = template.format(account=account)
        else:
            derivation_path = path
        return self._spending_key.derive_path(derivation_path)

    def full_viewing_key(self, path=None, account=0):
        return self.derive_spending_key(path, account).to_full_viewing_key()

    def incoming_viewing_key(self, path=None, account=0):
        return self.full_viewing_key(path, account).incoming_viewing_key

    def payment_address(
        self,
        diversifier_index=0,
        path=None,
        internal=False,
        account=0,
    ):
        viewing_key = self.full_viewing_key(path, account)
        if internal:
            viewing_key = viewing_key.derive_internal()
        return viewing_key.derive_address(
            diversifier_index,
            self.network,
        )

    def default_payment_address(self, path=None, internal=False, account=0):
        viewing_key = self.full_viewing_key(path, account)
        if internal:
            viewing_key = viewing_key.derive_internal()
        return viewing_key.default_address(self.network)
