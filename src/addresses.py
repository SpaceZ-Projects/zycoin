"""Sapling network parameters and payment address encoding."""

from dataclasses import dataclass

from .coins import get_coin_network
from .jubjub import Point, group_hash
from .serialization import bech32_encode, bech32_decode


class SaplingCapabilityError(ValueError):
    """Raised when a coin or network lacks verified Sapling wallet support."""


@dataclass(frozen=True)
class SaplingNetwork:
    name: str
    coin: str
    capability_status: str
    sapling_activation_height: int
    payment_address_hrp: str
    full_viewing_key_hrp: str
    incoming_viewing_key_hrp: str
    extended_spending_key_hrp: str
    coin_type: int
    default_derivation_path: str = None

    @property
    def wallet_derivation_supported(self):
        return (
            self.capability_status == "supported_verified_parameters"
            and self.default_derivation_path is not None
        )


def get_network(name):
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Sapling network must be specified as coin-network")
    parts = name.strip().lower().split("-", 1)
    if len(parts) != 2:
        raise ValueError(f"invalid Sapling network identifier: {name}")
    coin_id, network_id = parts
    config = get_coin_network(coin_id, network_id)
    parameters = config.sapling
    if parameters.get("status") not in {
        "supported_verified_parameters",
        "partial",
    }:
        raise SaplingCapabilityError(
            f"Sapling parameters are not verified for {coin_id} {network_id}"
        )
    required = (
        "activation_height",
        "zip32_coin_type",
        "payment_address_hrp",
        "full_viewing_key_hrp",
        "incoming_viewing_key_hrp",
        "extended_spending_key_hrp",
    )
    if any(parameters.get(field) is None for field in required):
        raise SaplingCapabilityError(
            f"incomplete Sapling parameters for {coin_id} {network_id}"
        )
    return SaplingNetwork(
        name=f"{coin_id}-{network_id}",
        coin=coin_id,
        capability_status=parameters["status"],
        sapling_activation_height=parameters["activation_height"],
        payment_address_hrp=parameters["payment_address_hrp"],
        full_viewing_key_hrp=parameters["full_viewing_key_hrp"],
        incoming_viewing_key_hrp=parameters["incoming_viewing_key_hrp"],
        extended_spending_key_hrp=parameters["extended_spending_key_hrp"],
        coin_type=parameters["zip32_coin_type"],
        default_derivation_path=parameters.get("derivation_path"),
    )


@dataclass(frozen=True)
class SaplingPaymentAddress:
    diversifier: bytes
    transmission_key: bytes
    network: SaplingNetwork

    def __post_init__(self):
        if len(self.diversifier) != 11 or len(self.transmission_key) != 32:
            raise ValueError("invalid Sapling payment address components")
        point = Point.from_bytes(self.transmission_key, check_subgroup=True)
        if point.u == 0 and point.v == 1:
            raise ValueError("Sapling transmission key cannot be the identity")

    @property
    def raw(self):
        return self.diversifier + self.transmission_key

    def encode(self):
        return bech32_encode(self.network.payment_address_hrp, self.raw)

    @classmethod
    def decode(cls, encoded, network):
        hrp, raw = bech32_decode(encoded)
        if hrp != network.payment_address_hrp:
            raise ValueError("Sapling payment address belongs to another network")
        if len(raw) != 43:
            raise ValueError("invalid Sapling payment address length")
        return cls(raw[:11], raw[11:], network)


def derive_payment_address(ivk, diversifier, network):
    if not network.wallet_derivation_supported:
        raise SaplingCapabilityError(
            f"Sapling wallet derivation is not verified for {network.name}"
        )
    if (
        isinstance(ivk, bool)
        or not isinstance(ivk, int)
        or not 0 < ivk < (1 << 251)
    ):
        raise ValueError("incoming viewing key must be a non-zero 251-bit value")
    if not isinstance(diversifier, bytes) or len(diversifier) != 11:
        raise ValueError("Sapling diversifier must be exactly 11 bytes")
    diversifier_base = group_hash(b"Zcash_gd", diversifier)
    if diversifier_base is None:
        raise ValueError("invalid Sapling diversifier")
    transmission_key = diversifier_base.multiply(ivk).encode()
    return SaplingPaymentAddress(diversifier, transmission_key, network)


def decode_incoming_viewing_key(encoded, network):
    hrp, data = bech32_decode(encoded)
    if hrp != network.incoming_viewing_key_hrp:
        raise ValueError("Sapling incoming viewing key belongs to another network")
    if len(data) != 32:
        raise ValueError("Sapling incoming viewing keys must be 32 bytes")
    ivk = int.from_bytes(data, "little")
    if not 0 < ivk < (1 << 251):
        raise ValueError("invalid Sapling incoming viewing key")
    return ivk
