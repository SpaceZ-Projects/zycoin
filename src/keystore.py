
from .crypto import *
from .coins import (
    CoinNetworkConfig,
    ConfigurationError,
    get_active_network,
    get_coin_network,
)
from .mnemonic import mnemonic_to_seed, validate_mnemonic

is_seed = validate_mnemonic


def _network_for_data(data, network=None):
    if network is not None:
        if not isinstance(network, CoinNetworkConfig):
            raise TypeError("wallet network must be a loaded coin network config")
        return network
    coin_id = data.get("coin_id")
    network_id = data.get("network_id")
    if not coin_id or not network_id:
        return get_active_network()
    return get_coin_network(coin_id, network_id)

class KeyStore():

    def has_seed(self):
        return False

    def is_watching_only(self):
        return False

    def can_import(self):
        return False

    def may_have_password(self):
        """Returns whether the keystore can be encrypted with a password."""
        raise NotImplementedError()

    def get_tx_derivations(self, tx):
        keypairs = {}
        for txin in tx.inputs():
            num_sig = txin.get('num_sig')
            if num_sig is None:
                continue
            x_signatures = txin['signatures']
            signatures = [sig for sig in x_signatures if sig]
            if len(signatures) == num_sig:
                # input is complete
                continue
            for k, x_pubkey in enumerate(txin['x_pubkeys']):
                if x_signatures[k] is not None:
                    # this pubkey already signed
                    continue
                derivation = self.get_pubkey_derivation(x_pubkey)
                if not derivation:
                    continue
                keypairs[x_pubkey] = derivation
        return keypairs

    def can_sign(self, tx):
        if self.is_watching_only():
            return False
        return bool(self.get_tx_derivations(tx))

    def ready_to_sign(self):
        return not self.is_watching_only()


class Software_KeyStore(KeyStore):

    def __init__(self):
        KeyStore.__init__(self)

    def may_have_password(self):
        return not self.is_watching_only()

    def sign_message(self, sequence, message, password):
        privkey, compressed = self.get_private_key(sequence, password)
        key = regenerate_key(privkey)
        return key.sign_message(message, compressed)

    def decrypt_message(self, sequence, message, password):
        privkey, compressed = self.get_private_key(sequence, password)
        ec = regenerate_key(privkey)
        decrypted = ec.decrypt_message(message)
        return decrypted

    def sign_transaction(self, tx, password):
        if self.is_watching_only():
            return
        # Raise if password is not correct.
        self.check_password(password)
        # Add private keys
        keypairs = self.get_tx_derivations(tx)
        for k, v in keypairs.items():
            keypairs[k] = self.get_private_key(v, password)
        # Sign
        if keypairs:
            tx.sign(keypairs)


class Imported_KeyStore(Software_KeyStore):
    # keystore for imported private keys

    def __init__(self, d):
        Software_KeyStore.__init__(self)
        self.network = _network_for_data(d)
        self.keypairs = d.get('keypairs', {})
        self._password_protected = bool(d.get("password_protected", False))

    def is_deterministic(self):
        return False

    def get_master_public_key(self):
        return None

    def dump(self):
        if self.keypairs and not self._password_protected:
            raise ValueError("imported private keys must be encrypted before saving")
        return {
            'type': 'imported',
            'keypairs': self.keypairs,
            'coin_id': self.network.coin_id,
            'network_id': self.network.network_id,
            'password_protected': self._password_protected,
        }

    def can_import(self):
        return True

    def check_password(self, password):
        pubkey = list(self.keypairs.keys())[0]
        self.get_private_key(pubkey, password)

    def import_privkey(self, sec, password):
        if not password:
            raise ValueError("a non-empty wallet password is required")
        txin_type, privkey, compressed = deserialize_privkey(
            sec, self.network
        )
        pubkey = public_key_from_private_key(privkey, compressed)
        # re-serialize the key so the internal storage format is consistent
        serialized_privkey = serialize_privkey(
            privkey, compressed, txin_type, internal_use=True,
            net=self.network,
        )
        # NOTE: if the same pubkey is reused for multiple addresses (script types),
        # there will only be one pubkey-privkey pair for it in self.keypairs,
        # and the privkey will encode a txin_type but that txin_type cannot be trusted.
        # Removing keys complicates this further.
        self.keypairs[pubkey] = pw_encode(serialized_privkey, password)
        self._password_protected = True
        return txin_type, pubkey

    def delete_imported_key(self, key):
        self.keypairs.pop(key)

    def get_private_key(self, pubkey, password):
        sec = pw_decode(self.keypairs[pubkey], password)
        txin_type, privkey, compressed = deserialize_privkey(
            sec, self.network
        )
        # this checks the password
        if pubkey != public_key_from_private_key(privkey, compressed):
            raise Exception("")
        return privkey, compressed

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey[0:2] in ['02', '03', '04']:
            if x_pubkey in self.keypairs.keys():
                return x_pubkey
        elif x_pubkey[0:2] == 'fd':
            addr = script_to_address(x_pubkey[2:])
            if addr in self.addresses:
                return self.addresses[addr].get('pubkey')

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        for k, v in self.keypairs.items():
            b = pw_decode(v, old_password)
            c = pw_encode(b, new_password)
            self.keypairs[k] = c
        self._password_protected = bool(new_password)



class Deterministic_KeyStore(Software_KeyStore):

    def __init__(self, d):
        Software_KeyStore.__init__(self)
        self.seed = d.get('seed', '')
        self.passphrase = d.get('passphrase', '')

    def is_deterministic(self):
        return True

    def dump(self):
        d = {}
        if self.seed:
            d['seed'] = self.seed
        if self.passphrase:
            d['passphrase'] = self.passphrase
        return d

    def has_seed(self):
        return bool(self.seed)

    def is_watching_only(self):
        return not self.has_seed()

    def add_seed(self, seed):
        if self.seed:
            raise Exception("a seed exists")
        self.seed = self.format_seed(seed)

    def get_seed(self, password):
        return pw_decode(self.seed, password)

    def get_passphrase(self, password):
        return pw_decode(self.passphrase, password) if self.passphrase else ''


class Xpub:

    def __init__(self):
        self.xpub = None
        self.xpub_receive = None
        self.xpub_change = None

    def get_master_public_key(self):
        return self.xpub

    def derive_pubkey(self, for_change, n):
        xpub = self.xpub_change if for_change else self.xpub_receive
        if xpub is None:
            xpub = bip32_public_derivation(
                self.xpub,
                "",
                "/%d" % for_change,
                net=self.network,
            )
            if for_change:
                self.xpub_change = xpub
            else:
                self.xpub_receive = xpub
        return self.get_pubkey_from_xpub(xpub, (n,), net=self.network)

    @classmethod
    def get_pubkey_from_xpub(self, xpub, sequence, *, net=None):
        _, _, _, _, c, cK = deserialize_xpub(xpub, net=net)
        for i in sequence:
            cK, c = CKD_pub(cK, c, i)
        return bh2u(cK)

    def get_xpubkey(self, c, i):
        s = ''.join(map(lambda x: int_to_hex(x,2), (c, i)))
        return 'ff' + bh2u(DecodeBase58Check(self.xpub)) + s

    @classmethod
    def parse_xpubkey(self, pubkey):
        assert pubkey[0:2] == 'ff'
        pk = bfh(pubkey)
        pk = pk[1:]
        xkey = EncodeBase58Check(pk[0:78])
        dd = pk[78:]
        s = []
        while dd:
            n = int(rev_hex(bh2u(dd[0:2])), 16)
            dd = dd[2:]
            s.append(n)
        assert len(s) == 2
        return xkey, s

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey[0:2] != 'ff':
            return
        xpub, derivation = self.parse_xpubkey(x_pubkey)
        if self.xpub != xpub:
            return
        return derivation


class BIP32_KeyStore(Deterministic_KeyStore, Xpub):

    def __init__(self, d):
        Xpub.__init__(self)
        Deterministic_KeyStore.__init__(self, d)
        if self.seed and d.get("mnemonic_format") != "bip39":
            raise ConfigurationError(
                "wallet seed is not marked as a 24-word BIP-39 phrase"
            )
        self.network = _network_for_data(d)
        self.xpub = d.get('xpub')
        self.xprv = d.get('xprv')
        self._password_protected = bool(d.get("password_protected", False))

    def get_seed(self, password):
        seed = Deterministic_KeyStore.get_seed(self, password)
        if not validate_mnemonic(seed):
            raise ValueError("stored recovery phrase is not valid 24-word BIP-39")
        return seed

    def format_seed(self, seed):
        if not validate_mnemonic(seed):
            raise ValueError("wallet recovery phrase must be valid 24-word BIP-39")
        return ' '.join(seed.split())

    def dump(self):
        if (self.seed or self.xprv) and not self._password_protected:
            raise ValueError("recovery phrases and private keys must be encrypted before saving")
        d = Deterministic_KeyStore.dump(self)
        d['type'] = 'bip32'
        d['xpub'] = self.xpub
        d['xprv'] = self.xprv
        if self.seed:
            d["mnemonic_format"] = "bip39"
        d['coin_id'] = self.network.coin_id
        d['network_id'] = self.network.network_id
        d["password_protected"] = self._password_protected
        return d

    def get_master_private_key(self, password):
        return pw_decode(self.xprv, password)

    def check_password(self, password):
        xprv = pw_decode(self.xprv, password)
        if (
            deserialize_xprv(xprv, net=self.network)[4]
            != deserialize_xpub(self.xpub, net=self.network)[4]
        ):
            raise Exception("")

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        if self.has_seed():
            decoded = self.get_seed(old_password)
            self.seed = pw_encode(decoded, new_password)
        if self.passphrase:
            decoded = self.get_passphrase(old_password)
            self.passphrase = pw_encode(decoded, new_password)
        if self.xprv is not None:
            b = pw_decode(self.xprv, old_password)
            self.xprv = pw_encode(b, new_password)
        self._password_protected = bool(new_password)

    def is_watching_only(self):
        return self.xprv is None

    def add_xprv(self, xprv):
        self.xprv = xprv
        self.xpub = xpub_from_xprv(xprv, net=self.network)

    def add_xprv_from_seed(self, bip32_seed, xtype, derivation):
        xprv, xpub = bip32_root(bip32_seed, xtype, net=self.network)
        xprv, xpub = bip32_private_derivation(
            xprv,
            "m/",
            derivation,
            net=self.network,
        )
        self.add_xprv(xprv)

    def get_private_key(self, sequence, password):
        xprv = self.get_master_private_key(password)
        _, _, _, _, c, k = deserialize_xprv(xprv, net=self.network)
        pk = bip32_private_key(sequence, k, c)
        return pk, True



def bip39_to_seed(mnemonic, passphrase=""):
    return mnemonic_to_seed(mnemonic, passphrase)


def bip39_is_checksum_valid(mnemonic):
    """Return checksum validity and whether every token is in the wordlist."""
    from .mnemonic import _wordlist

    if not isinstance(mnemonic, str):
        return False, False
    words = mnemonic.split()
    word_set = set(_wordlist())
    valid_words = all(word in word_set for word in words)
    return validate_mnemonic(mnemonic), valid_words


def from_bip39_seed(
    seed,
    passphrase,
    derivation,
    coin,
    network="mainnet",
    *,
    password=None,
):
    if password is not None and (
        not isinstance(password, str) or not password
    ):
        raise ValueError("a non-empty wallet password is required")
    network_config = get_coin_network(coin, network)
    keystore = BIP32_KeyStore({
        "coin_id": network_config.coin_id,
        "network_id": network_config.network_id,
    })
    keystore.add_seed(seed)
    keystore.passphrase = passphrase
    keystore.add_xprv_from_seed(
        mnemonic_to_seed(seed, passphrase),
        xtype_from_derivation(derivation),
        derivation,
    )
    if password is not None:
        keystore.update_password(None, password)
    return keystore


def xtype_from_derivation(derivation):
    """Returns the script type to be used for this derivation."""
    if derivation.startswith("m/84'") or derivation.startswith("m/49'"):
        raise Exception('Unknown bip43 derivation purpose %s' % derivation[:5])
    else:
        return 'standard'


# extended pubkeys

def is_xpubkey(x_pubkey):
    return x_pubkey[0:2] == 'ff'


def parse_xpubkey(x_pubkey):
    assert x_pubkey[0:2] == 'ff'
    return BIP32_KeyStore.parse_xpubkey(x_pubkey)


def xpubkey_to_address(x_pubkey, network=None):
    if x_pubkey[0:2] == 'fd':
        address = script_to_address(x_pubkey[2:], net=network)
        return x_pubkey, address
    if x_pubkey[0:2] in ['02', '03', '04']:
        pubkey = x_pubkey
    elif x_pubkey[0:2] == 'ff':
        xpub, s = BIP32_KeyStore.parse_xpubkey(x_pubkey)
        pubkey = BIP32_KeyStore.get_pubkey_from_xpub(xpub, s, net=network)
    else:
        raise Exception("Cannot parse pubkey. prefix: {}"
                               .format(x_pubkey[0:2]))
    if pubkey:
        address = public_key_to_p2pkh(bfh(pubkey), network)
    return pubkey, address

def xpubkey_to_pubkey(x_pubkey, network=None):
    pubkey, address = xpubkey_to_address(x_pubkey, network)
    return pubkey

hw_keystores = {}

def register_keystore(hw_type, constructor):
    hw_keystores[hw_type] = constructor

def hardware_keystore(d):
    hw_type = d['hw_type']
    if hw_type in hw_keystores:
        constructor = hw_keystores[hw_type]
        return constructor(d)
    raise Exception('unknown hardware type: {}'.format(hw_type))

def load_keystore(storage, name):
    d = storage.get(name, {})
    t = d.get('type')
    if not t:
        raise Exception(
            'Wallet format requires update.\n'
            'Cannot find keystore for name {}'.format(name))
    if t == 'old':
        raise ConfigurationError(
            "legacy Electrum wallets are unsupported; use a 24-word BIP-39 phrase"
        )
    if t == 'imported':
        k = Imported_KeyStore(d)
    elif t == 'bip32':
        k = BIP32_KeyStore(d)
    elif t == 'hardware':
        k = hardware_keystore(d)
    else:
        raise Exception(
            'Unknown type {} for keystore named {}'.format(t, name))
    return k


def is_address_list(text, network=None):
    parts = text.split()
    return bool(parts) and all(is_address(x, network) for x in parts)


def get_private_keys(text, network=None):
    parts = text.split('\n')
    parts = map(lambda x: ''.join(x.split()), parts)
    parts = list(filter(bool, parts))
    if bool(parts) and all(is_private_key(x, network) for x in parts):
        return parts


def is_private_key_list(text, network=None):
    return bool(get_private_keys(text, network))


def is_private_key(text, network=None):
    if is_xprv(text, network):
        return True
    try:
        deserialize_privkey(text, network)
        return True
    except Exception:
        return False


def is_private(text, network=None):
    return is_seed(text) or is_xprv(text, network) or is_private_key_list(text, network)


def is_master_key(text, network=None):
    return is_xprv(text, network) or is_xpub(text, network)


def is_bip32_key(text, network=None):
    return is_xprv(text, network) or is_xpub(text, network)


def bip44_derivation(account_id, coin, network="mainnet", purpose=44):
    network_config = get_coin_network(coin, network)
    parameters = network_config.transparent_derivation
    coin_type = parameters.get("coin_type")
    path_template = parameters.get("path")
    if (
        coin_type is None
        or parameters.get("status") != "supported_verified_parameters"
        or path_template is None
    ):
        raise ConfigurationError(
            f"verified transparent coin type is unavailable for {coin} {network}"
        )
    if (
        isinstance(account_id, bool)
        or not isinstance(account_id, int)
        or not 0 <= account_id < BIP32_PRIME
    ):
        raise ValueError("account_id must be in [0, 2^31)")
    if isinstance(purpose, bool) or not isinstance(purpose, int) or purpose != 44:
        raise ValueError("only the configured BIP44 purpose 44 is supported")
    expected_template = f"m/44'/{coin_type}'/{{account}}'"
    if path_template != expected_template:
        raise ConfigurationError(
            f"configured BIP44 path is inconsistent for {coin} {network}"
        )
    return path_template.format(account=account_id)


def from_private_key_list(
    text,
    coin,
    network="mainnet",
    *,
    password,
):
    if not password:
        raise ValueError("a non-empty wallet password is required")
    network_config = get_coin_network(coin, network)
    keystore = Imported_KeyStore({
        "coin_id": network_config.coin_id,
        "network_id": network_config.network_id,
    })
    for key in get_private_keys(text, network_config):
        keystore.import_privkey(key, password)
    return keystore


def from_xpub(xpub, coin, network="mainnet"):
    network_config = get_coin_network(coin, network)
    k = BIP32_KeyStore({
        "coin_id": network_config.coin_id,
        "network_id": network_config.network_id,
    })
    k.xpub = xpub
    deserialize_xpub(xpub, net=network_config)
    return k


def from_xprv(xprv, coin, network="mainnet", *, password):
    if not password:
        raise ValueError("a non-empty wallet password is required")
    network_config = get_coin_network(coin, network)
    xpub = xpub_from_xprv(xprv, net=network_config)
    k = BIP32_KeyStore({
        "coin_id": network_config.coin_id,
        "network_id": network_config.network_id,
    })
    k.xprv = pw_encode(xprv, password)
    k.xpub = xpub
    k._password_protected = True
    return k


def from_master_key(text, coin, network="mainnet", *, password=None):
    network_config = get_coin_network(coin, network)
    if is_xprv(text, network_config):
        k = from_xprv(text, coin, network, password=password)
    elif is_xpub(text, network_config):
        k = from_xpub(text, coin, network)
    else:
        raise Exception('Invalid master key')
    return k
