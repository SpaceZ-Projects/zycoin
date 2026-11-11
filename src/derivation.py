"""ZIP 32 Sapling extended spending and viewing key derivation."""

from dataclasses import dataclass
from hashlib import blake2b, blake2s

import pyaes

from .addresses import SaplingCapabilityError, derive_payment_address
from .jubjub import (
    IDENTITY,
    SCALAR_MODULUS,
    Point,
    group_hash,
    proving_key_base,
    spending_key_base,
)

HARDENED = 1 << 31


def _prf_expand(secret, tag):
    digest = blake2b(digest_size=64, person=b"Zcash_ExpandSeed")
    digest.update(secret)
    digest.update(tag)
    return digest.digest()


def _to_scalar(data):
    return int.from_bytes(data, "little") % SCALAR_MODULUS


def _encode_scalar(value):
    return (value % SCALAR_MODULUS).to_bytes(32, "little")


def _encode_xsk_parts(ask, nsk, ovk, dk):
    return _encode_scalar(ask) + _encode_scalar(nsk) + ovk + dk


def _encode_xfvk_parts(ak, nk, ovk, dk):
    return ak + nk + ovk + dk


def _ivk(ak, nk):
    digest = blake2s(digest_size=32, person=b"Zcashivk")
    digest.update(ak)
    digest.update(nk)
    result = int.from_bytes(digest.digest(), "little") & ((1 << 251) - 1)
    if result == 0:
        raise ValueError("invalid Sapling key: zero incoming viewing key")
    return result


def _index_to_little_endian_bits(index):
    return [(index >> bit) & 1 for bit in range(88)]


def _bits_to_little_endian_bytes(bits):
    return bytes(
        sum(bit << offset for offset, bit in enumerate(bits[start:start + 8]))
        for start in range(0, len(bits), 8)
    )


def _bits_to_big_endian_bytes(bits):
    padding = (-len(bits)) % 8
    padded = [0] * padding + bits
    return bytes(
        _bits_to_big_endian_integer(padded[start:start + 8])
        for start in range(0, len(padded), 8)
    )


def _bits_to_big_endian_integer(bits):
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _integer_to_big_endian_bits(value, width):
    return [(value >> shift) & 1 for shift in range(width - 1, -1, -1)]


def _aes_cbc_mac(key, message):
    if len(key) != 32 or len(message) % 16:
        raise ValueError("FF1 AES input must use a 32-byte key and full blocks")
    aes = pyaes.AES(key)
    state = b"\x00" * 16
    for offset in range(0, len(message), 16):
        block = bytes(a ^ b for a, b in zip(state, message[offset:offset + 16]))
        state = aes.encrypt(block)
    return state


def _ff1_88_encrypt(key, bits):
    if len(bits) != 88 or any(bit not in (0, 1) for bit in bits):
        raise ValueError("Sapling diversifier indices must be 88 bits")
    u = 44
    a, b = bits[:u], bits[u:]
    p = bytes((1, 2, 1, 0, 0, 2, 10, u, 0, 0, 0, 88, 0, 0, 0, 0))
    for round_number in range(10):
        q = bytes((round_number,)) + _bits_to_big_endian_bytes(b)
        q = b"\x00" * ((-len(q)) % 16) + q
        y = int.from_bytes(_aes_cbc_mac(key, p + q)[:12], "big")
        c = (_bits_to_big_endian_integer(a) + y) % (1 << u)
        a, b = b, _integer_to_big_endian_bits(c, u)
    return a + b


def _derive_diversifier(dk, index):
    if not isinstance(index, int) or not 0 <= index < (1 << 88):
        raise ValueError("Sapling diversifier index must be in [0, 2^88)")
    bits = _ff1_88_encrypt(dk, _index_to_little_endian_bits(index))
    return _bits_to_little_endian_bytes(bits)


@dataclass(frozen=True)
class ExtendedFullViewingKey:
    ak: bytes
    nk: bytes
    ovk: bytes
    dk: bytes
    chain_code: bytes
    depth: int = 0
    parent_tag: bytes = b"\x00" * 4
    child_index: int = 0

    def __post_init__(self):
        if any(len(part) != 32 for part in (
            self.ak, self.nk, self.ovk, self.dk, self.chain_code
        )):
            raise ValueError("extended viewing key components must be 32 bytes")
        if (
            len(self.parent_tag) != 4
            or isinstance(self.depth, bool)
            or not isinstance(self.depth, int)
            or not 0 <= self.depth <= 255
        ):
            raise ValueError("invalid extended viewing key metadata")
        if (
            isinstance(self.child_index, bool)
            or not isinstance(self.child_index, int)
            or not 0 <= self.child_index < (1 << 32)
        ):
            raise ValueError("invalid extended viewing key child index")
        if Point.from_bytes(self.ak, check_subgroup=True) == IDENTITY:
            raise ValueError("invalid Sapling full viewing key")
        Point.from_bytes(self.nk, check_subgroup=True)

    @property
    def incoming_viewing_key(self):
        return _ivk(self.ak, self.nk)

    def serialize(self):
        return (
            bytes((self.depth,))
            + self.parent_tag
            + self.child_index.to_bytes(4, "little")
            + self.chain_code
            + _encode_xfvk_parts(self.ak, self.nk, self.ovk, self.dk)
        )

    @classmethod
    def deserialize(cls, data):
        if not isinstance(data, bytes) or len(data) != 169:
            raise ValueError("extended Sapling full viewing keys must be 169 bytes")
        depth = data[0]
        parent_tag = data[1:5]
        child_index = int.from_bytes(data[5:9], "little")
        chain_code = data[9:41]
        ak = data[41:73]
        nk = data[73:105]
        ovk = data[105:137]
        dk = data[137:169]
        return cls(
            ak,
            nk,
            ovk,
            dk,
            chain_code,
            depth,
            parent_tag,
            child_index,
        )

    def encode(self, network):
        from .serialization import bech32_encode

        return bech32_encode(network.full_viewing_key_hrp, self.serialize())

    @classmethod
    def decode(cls, encoded, network):
        from .serialization import bech32_decode

        hrp, data = bech32_decode(encoded)
        if hrp != network.full_viewing_key_hrp:
            raise ValueError("extended Sapling viewing key belongs to another network")
        return cls.deserialize(data)

    def encode_incoming_viewing_key(self, network):
        from .serialization import bech32_encode

        return bech32_encode(
            network.incoming_viewing_key_hrp,
            _encode_scalar(self.incoming_viewing_key),
        )

    @staticmethod
    def decode_incoming_viewing_key(encoded, network):
        from .addresses import decode_incoming_viewing_key

        return decode_incoming_viewing_key(encoded, network)

    @property
    def outgoing_viewing_key(self):
        return self.ovk

    def fingerprint(self):
        digest = blake2b(digest_size=32, person=b"ZcashSaplingFVFP")
        digest.update(self.ak + self.nk + self.ovk)
        return digest.digest()

    def derive_child(self, index):
        if not isinstance(index, int) or not 0 <= index < HARDENED:
            raise ValueError("full viewing keys derive non-hardened children only")
        return _derive_child(self, index)

    def derive_internal(self):
        digest = blake2b(digest_size=32, person=b"Zcash_SaplingInt")
        digest.update(_encode_xfvk_parts(self.ak, self.nk, self.ovk, self.dk))
        intermediate = digest.digest()
        internal_nsk = _to_scalar(_prf_expand(intermediate, b"\x17"))
        output = _prf_expand(intermediate, b"\x18")
        nk_point = (
            proving_key_base().multiply(internal_nsk)
            + _decode_point(self.nk)
        ).encode()
        return ExtendedFullViewingKey(
            ak=self.ak,
            nk=nk_point,
            ovk=output[32:],
            dk=output[:32],
            chain_code=self.chain_code,
            depth=self.depth,
            parent_tag=self.parent_tag,
            child_index=self.child_index,
        )

    def derive_address(self, diversifier_index, network):
        if not network.wallet_derivation_supported:
            raise SaplingCapabilityError(
                f"Sapling wallet derivation is not verified for {network.name}"
            )
        for index in range(diversifier_index, 1 << 88):
            diversifier = _derive_diversifier(self.dk, index)
            if group_hash(b"Zcash_gd", diversifier) is not None:
                return derive_payment_address(
                    self.incoming_viewing_key,
                    diversifier,
                    network,
                )
        raise ValueError("no valid Sapling diversifier remains")

    def default_address(self, network):
        return self.derive_address(0, network)


def _decode_point(encoded):
    return Point.from_bytes(encoded, check_subgroup=True)


def _derive_child(parent, index):
    if (
        isinstance(index, bool)
        or not isinstance(index, int)
        or not 0 <= index < (1 << 32)
    ):
        raise ValueError("ZIP32 child index must be a uint32")
    hardened = index >= HARDENED
    has_spending_key = isinstance(parent, ExtendedSpendingKey)
    if hardened:
        if not has_spending_key:
            raise ValueError("cannot derive hardened children from a viewing key")
        prefix = b"\x11" + _encode_xsk_parts(
            parent.ask, parent.nsk, parent.ovk, parent.dk
        )
    else:
        prefix = b"\x12" + _encode_xfvk_parts(
            parent.ak, parent.nk, parent.ovk, parent.dk
        )
    expanded = _prf_expand(
        parent.chain_code,
        prefix + index.to_bytes(4, "little"),
    )
    left, right = expanded[:32], expanded[32:]
    ask_delta = _to_scalar(_prf_expand(left, b"\x13"))
    nsk_delta = _to_scalar(_prf_expand(left, b"\x14"))
    ovk = _prf_expand(left, b"\x15" + parent.ovk)[:32]
    dk = _prf_expand(left, b"\x16" + parent.dk)[:32]

    if has_spending_key:
        ask = (ask_delta + parent.ask) % SCALAR_MODULUS
        nsk = (nsk_delta + parent.nsk) % SCALAR_MODULUS
        result = ExtendedSpendingKey(
            ask=ask,
            nsk=nsk,
            ovk=ovk,
            dk=dk,
            chain_code=right,
            depth=parent.depth + 1,
            parent_tag=parent.fingerprint()[:4],
            child_index=index,
        )
    else:
        ak = (
            spending_key_base().multiply(ask_delta)
            + _decode_point(parent.ak)
        ).encode()
        nk = (
            proving_key_base().multiply(nsk_delta)
            + _decode_point(parent.nk)
        ).encode()
        result = ExtendedFullViewingKey(
            ak=ak,
            nk=nk,
            ovk=ovk,
            dk=dk,
            chain_code=right,
            depth=parent.depth + 1,
            parent_tag=parent.fingerprint()[:4],
            child_index=index,
        )
    _ivk(result.ak, result.nk)
    return result


@dataclass(frozen=True)
class ExtendedSpendingKey:
    ask: int
    nsk: int
    ovk: bytes
    dk: bytes
    chain_code: bytes
    depth: int = 0
    parent_tag: bytes = b"\x00" * 4
    child_index: int = 0

    def __post_init__(self):
        if (
            isinstance(self.ask, bool)
            or not isinstance(self.ask, int)
            or not 0 < self.ask < SCALAR_MODULUS
            or isinstance(self.nsk, bool)
            or not isinstance(self.nsk, int)
            or not 0 <= self.nsk < SCALAR_MODULUS
        ):
            raise ValueError("invalid Sapling spending scalar")
        if any(len(part) != 32 for part in (self.ovk, self.dk, self.chain_code)):
            raise ValueError("extended spending key components must be 32 bytes")
        if (
            len(self.parent_tag) != 4
            or isinstance(self.depth, bool)
            or not isinstance(self.depth, int)
            or not 0 <= self.depth <= 255
        ):
            raise ValueError("invalid extended spending key metadata")
        if (
            isinstance(self.child_index, bool)
            or not isinstance(self.child_index, int)
            or not 0 <= self.child_index < (1 << 32)
        ):
            raise ValueError("invalid extended spending key child index")
        _ivk(self.ak, self.nk)

    @classmethod
    def master(cls, seed):
        if not isinstance(seed, bytes) or not 32 <= len(seed) <= 252:
            raise ValueError("ZIP32 seed must contain between 32 and 252 bytes")
        digest = blake2b(digest_size=64, person=b"ZcashIP32Sapling")
        digest.update(seed)
        expanded = digest.digest()
        spending_seed, chain_code = expanded[:32], expanded[32:]
        return cls(
            ask=_to_scalar(_prf_expand(spending_seed, b"\x00")),
            nsk=_to_scalar(_prf_expand(spending_seed, b"\x01")),
            ovk=_prf_expand(spending_seed, b"\x02")[:32],
            dk=_prf_expand(spending_seed, b"\x10")[:32],
            chain_code=chain_code,
        )

    @property
    def ak(self):
        return spending_key_base().multiply(self.ask).encode()

    @property
    def nk(self):
        return proving_key_base().multiply(self.nsk).encode()

    @property
    def incoming_viewing_key(self):
        return _ivk(self.ak, self.nk)

    def serialize(self):
        return (
            bytes((self.depth,))
            + self.parent_tag
            + self.child_index.to_bytes(4, "little")
            + self.chain_code
            + _encode_xsk_parts(self.ask, self.nsk, self.ovk, self.dk)
        )

    def encode(self, network):
        from .serialization import bech32_encode

        return bech32_encode(network.extended_spending_key_hrp, self.serialize())

    @classmethod
    def decode(cls, encoded, network):
        from .serialization import bech32_decode

        hrp, data = bech32_decode(encoded)
        if hrp != network.extended_spending_key_hrp:
            raise ValueError("extended Sapling spending key belongs to another network")
        return cls.deserialize(data)

    @classmethod
    def deserialize(cls, data):
        if not isinstance(data, bytes) or len(data) != 169:
            raise ValueError("extended Sapling spending keys must be 169 bytes")
        offset = 0
        depth = data[offset]
        offset += 1
        parent_tag = data[offset:offset + 4]
        offset += 4
        child_index = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4
        chain_code = data[offset:offset + 32]
        offset += 32
        ask = int.from_bytes(data[offset:offset + 32], "little")
        offset += 32
        nsk = int.from_bytes(data[offset:offset + 32], "little")
        offset += 32
        ovk = data[offset:offset + 32]
        offset += 32
        dk = data[offset:offset + 32]
        return cls(ask, nsk, ovk, dk, chain_code, depth, parent_tag, child_index)

    def to_full_viewing_key(self):
        return ExtendedFullViewingKey(
            self.ak,
            self.nk,
            self.ovk,
            self.dk,
            self.chain_code,
            self.depth,
            self.parent_tag,
            self.child_index,
        )

    def derive_child(self, index):
        return _derive_child(self, index)

    def derive_path(self, path):
        if not isinstance(path, str):
            raise ValueError("invalid ZIP32 derivation path")
        components = path.split("/")
        if not components or components[0] != "m":
            raise ValueError("ZIP32 derivation paths must start with 'm'")
        current = self
        for component in components[1:]:
            if not component:
                raise ValueError("invalid ZIP32 derivation path")
            hardened = component.endswith("'")
            value = component[:-1] if hardened else component
            if not value or any(char < "0" or char > "9" for char in value):
                raise ValueError("invalid ZIP32 derivation path")
            index = int(value)
            if not 0 <= index < HARDENED:
                raise ValueError("ZIP32 path component is out of range")
            current = current.derive_child(index + (HARDENED if hardened else 0))
        return current

    def derive_internal(self):
        digest = blake2b(digest_size=32, person=b"Zcash_SaplingInt")
        digest.update(
            _encode_xfvk_parts(self.ak, self.nk, self.ovk, self.dk)
        )
        intermediate = digest.digest()
        internal_nsk = (
            _to_scalar(_prf_expand(intermediate, b"\x17")) + self.nsk
        ) % SCALAR_MODULUS
        output = _prf_expand(intermediate, b"\x18")
        return ExtendedSpendingKey(
            ask=self.ask,
            nsk=internal_nsk,
            ovk=output[32:],
            dk=output[:32],
            chain_code=self.chain_code,
            depth=self.depth,
            parent_tag=self.parent_tag,
            child_index=self.child_index,
        )

    def derive_internal_viewing_key(self):
        return self.to_full_viewing_key().derive_internal()

    @property
    def outgoing_viewing_key(self):
        return self.ovk

    def fingerprint(self):
        digest = blake2b(digest_size=32, person=b"ZcashSaplingFVFP")
        digest.update(self.ak + self.nk + self.ovk)
        return digest.digest()

    def derive_address(self, diversifier_index, network):
        return self.to_full_viewing_key().derive_address(
            diversifier_index,
            network,
        )

    def default_address(self, network):
        return self.derive_address(0, network)
