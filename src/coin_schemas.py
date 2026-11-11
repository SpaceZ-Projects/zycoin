"""Validated configuration types for coins and their networks."""

from dataclasses import dataclass
from typing import Any, Mapping, Optional

_HARDENED_INDEX_LIMIT = 1 << 31
_LIGHTWALLETD_RPCS = {
    "GetLightdInfo",
    "GetLatestBlock",
    "GetBlock",
    "GetBlockRange",
    "GetTransaction",
    "SendTransaction",
    "GetTaddressTxids",
    "GetTaddressTransactions",
}


class ConfigurationError(ValueError):
    """Raised when a coin or network configuration is invalid."""


def _require_mapping(value, path):
    if not isinstance(value, dict):
        raise ConfigurationError(f"{path} must be a JSON object")
    return value


def _require_text(value, path, *, allow_empty=False):
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ConfigurationError(f"{path} must be a non-empty string")
    return value


def _require_status(value, path):
    if value not in {
        "configured_unverified",
        "supported_verified_parameters",
        "partial",
        "unsupported",
        "unknown",
        "unverified",
    }:
        raise ConfigurationError(f"{path}.status is missing or invalid")
    return value


def _require_hex(value, path, *, length=None):
    if not isinstance(value, str):
        raise ConfigurationError(f"{path} must be a hex string or null")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ConfigurationError(f"{path} must be a valid hex string") from exc
    if length is not None and len(decoded) != length:
        raise ConfigurationError(f"{path} must encode exactly {length} bytes")
    return decoded


def _optional_uint(value, path):
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int) or value < 0
    ):
        raise ConfigurationError(f"{path} must be a non-negative integer or null")
    return value


@dataclass(frozen=True)
class CoinNetworkConfig:
    coin_id: str
    network_id: str
    name: str
    symbol: str
    verification: str
    address_verification: str
    wif_prefix: Optional[int]
    p2pkh_prefix: Optional[bytes]
    p2sh_prefix: Optional[bytes]
    bech32_hrp: Optional[str]
    electrum: Mapping[str, Any]
    bitcore: Mapping[str, Any]
    lightwalletd: Mapping[str, Any]
    transparent_derivation: Mapping[str, Any]
    transparent_signing: Mapping[str, Any]
    sapling: Mapping[str, Any]
    xpub_headers: Mapping[str, int]
    xprv_headers: Mapping[str, int]
    branch_id: Optional[int]

    @classmethod
    def from_mapping(cls, coin_id, coin, network_id, value):
        path = f"coins.{coin_id}.networks.{network_id}"
        if not isinstance(network_id, str) or not network_id.strip():
            raise ConfigurationError(f"{path} network identifier is invalid")
        value = _require_mapping(value, path)
        verification = _require_status(value.get("verification"), path)

        address = _require_mapping(value.get("address"), f"{path}.address")
        address_verification = address.get("verification")
        if address_verification not in {
            "verified",
            "configured_unverified",
            "unverified",
        }:
            raise ConfigurationError(
                f"{path}.address.verification is missing or invalid"
            )
        address_sources = address.get("verification_sources")
        if address_sources is not None and (
            not isinstance(address_sources, list)
            or not address_sources
            or not all(
                isinstance(item, str) and item.strip()
                for item in address_sources
            )
        ):
            raise ConfigurationError(
                f"{path}.address.verification_sources must be a non-empty "
                "string list"
            )
        electrum = _require_mapping(value.get("electrum"), f"{path}.electrum")
        bitcore = _require_mapping(value.get("bitcore"), f"{path}.bitcore")
        lightwalletd = _require_mapping(
            value.get("lightwalletd"), f"{path}.lightwalletd"
        )
        derivation = _require_mapping(
            value.get("transparent_derivation"),
            f"{path}.transparent_derivation",
        )
        sapling = _require_mapping(value.get("sapling"), f"{path}.sapling")
        signing = value.get(
            "transparent_signing",
            {"status": "unsupported"},
        )
        signing = _require_mapping(signing, f"{path}.transparent_signing")
        xkeys = _require_mapping(value.get("extended_key_headers"), f"{path}.extended_key_headers")
        if set(xkeys) != {"xpub", "xprv"}:
            raise ConfigurationError(
                f"{path}.extended_key_headers must define xpub and xprv"
            )
        xpub_headers = _parse_headers(xkeys["xpub"], f"{path}.extended_key_headers.xpub")
        xprv_headers = _parse_headers(xkeys["xprv"], f"{path}.extended_key_headers.xprv")

        for section_name, section in (
            ("electrum", electrum),
            ("bitcore", bitcore),
            ("lightwalletd", lightwalletd),
            ("transparent_derivation", derivation),
            ("transparent_signing", signing),
            ("sapling", sapling),
        ):
            _require_status(section.get("status"), f"{path}.{section_name}")
        if "note_decryption_status" in sapling:
            _require_status(
                sapling["note_decryption_status"],
                f"{path}.sapling.note_decryption_status",
            )
        for field in (
            "activation_height",
            "zip212_activation_height",
            "zip212_grace_period_blocks",
        ):
            if field in sapling:
                _optional_uint(
                    sapling[field],
                    f"{path}.sapling.{field}",
                )

        servers = electrum.get("servers")
        ports = electrum.get("ports")
        if not isinstance(servers, list) or not all(
            isinstance(server, str) and server.strip() for server in servers
        ):
            raise ConfigurationError(f"{path}.electrum.servers must be a string list")
        if not isinstance(ports, dict) or any(
            key not in {"tcp", "ssl", "websocket"} for key in ports
        ):
            raise ConfigurationError(f"{path}.electrum.ports must be a valid object")
        for key, port in ports.items():
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
            ):
                raise ConfigurationError(f"{path}.electrum.ports.{key} is invalid")
        if electrum["status"] == "configured_unverified" and (
            not servers or not ports
        ):
            raise ConfigurationError(
                f"{path}.electrum is marked configured but has no server or port"
            )

        endpoints = lightwalletd.get("endpoints")
        if not isinstance(endpoints, list) or not all(
            isinstance(endpoint, str) and endpoint.strip()
            for endpoint in endpoints
        ):
            raise ConfigurationError(
                f"{path}.lightwalletd.endpoints must be a string list"
            )
        implemented_rpcs = lightwalletd.get("implemented_rpcs")
        if not isinstance(implemented_rpcs, list) or not all(
            isinstance(rpc, str) and rpc.strip() for rpc in implemented_rpcs
        ):
            raise ConfigurationError(
                f"{path}.lightwalletd.implemented_rpcs must be a string list"
            )
        unknown_rpcs = set(implemented_rpcs) - _LIGHTWALLETD_RPCS
        if unknown_rpcs:
            raise ConfigurationError(
                f"{path}.lightwalletd.implemented_rpcs contains unsupported RPCs: "
                f"{', '.join(sorted(unknown_rpcs))}"
            )
        if len(implemented_rpcs) != len(set(implemented_rpcs)):
            raise ConfigurationError(
                f"{path}.lightwalletd.implemented_rpcs must not contain duplicates"
            )
        if lightwalletd["status"] == "configured_unverified" and (
            not endpoints or "GetLightdInfo" not in implemented_rpcs
        ):
            raise ConfigurationError(
                f"{path}.lightwalletd is marked configured without an endpoint "
                "and GetLightdInfo"
            )
        bitcore_api = bitcore.get("api_path")
        if bitcore_api is not None and not isinstance(bitcore_api, str):
            raise ConfigurationError(f"{path}.bitcore.api_path must be a string or null")
        for key in ("explorer_url", "socket_path"):
            field = bitcore.get(key)
            if field is not None and (
                not isinstance(field, str) or not field.strip()
            ):
                raise ConfigurationError(f"{path}.bitcore.{key} must be a string or null")
        if bitcore["status"] == "configured_unverified" and (
            not bitcore.get("explorer_url") or not bitcore_api
        ):
            raise ConfigurationError(
                f"{path}.bitcore is marked configured without an explorer API"
            )

        wif = address.get("wif_prefix")
        if wif is not None and (
            isinstance(wif, bool)
            or not isinstance(wif, int)
            or not 0 <= wif <= 255
        ):
            raise ConfigurationError(f"{path}.address.wif_prefix must be a byte or null")
        p2pkh = address.get("p2pkh_prefix_hex")
        p2sh = address.get("p2sh_prefix_hex")
        hrp = address.get("bech32_hrp")
        if p2pkh is not None:
            p2pkh = _require_hex(p2pkh, f"{path}.address.p2pkh_prefix_hex")
            if len(p2pkh) not in (1, 2):
                raise ConfigurationError(
                    f"{path}.address.p2pkh_prefix_hex must encode one or two bytes"
                )
        if p2sh is not None:
            p2sh = _require_hex(p2sh, f"{path}.address.p2sh_prefix_hex")
            if len(p2sh) not in (1, 2):
                raise ConfigurationError(
                    f"{path}.address.p2sh_prefix_hex must encode one or two bytes"
                )
        if hrp is not None:
            _require_text(hrp, f"{path}.address.bech32_hrp")
        if address_verification == "verified" and any(
            item is None for item in (wif, p2pkh, p2sh)
        ):
            raise ConfigurationError(
                f"{path}.address is missing verified serialization prefixes"
            )
        if address_verification == "verified" and not address_sources:
            raise ConfigurationError(
                f"{path}.address is missing verification sources"
            )

        derivation_path = derivation.get("path")
        if derivation_path is not None:
            _require_text(derivation_path, f"{path}.transparent_derivation.path")
        coin_type = _optional_uint(
            derivation.get("coin_type"),
            f"{path}.transparent_derivation.coin_type",
        )
        derivation_sources = derivation.get("verification_sources")
        if derivation_sources is not None and (
            not derivation_sources
            or not isinstance(derivation_sources, list)
            or not all(
                isinstance(item, str) and item.strip()
                for item in derivation_sources
            )
        ):
            raise ConfigurationError(
                f"{path}.transparent_derivation.verification_sources "
                "must be a non-empty string list"
            )
        if derivation["status"] == "supported_verified_parameters" and (
            derivation_path is None
            or coin_type is None
            or not derivation_sources
        ):
            raise ConfigurationError(
                f"{path}.transparent_derivation is missing verified parameters"
            )
        if coin_type is not None and coin_type >= _HARDENED_INDEX_LIMIT:
            raise ConfigurationError(
                f"{path}.transparent_derivation.coin_type must fit a hardened BIP44 index"
            )
        if derivation["status"] == "supported_verified_parameters" and (
            derivation_path != f"m/44'/{coin_type}'/{{account}}'"
        ):
            raise ConfigurationError(
                f"{path}.transparent_derivation.path must use the configured "
                "BIP44 coin type and account"
            )
        if derivation["status"] == "supported_verified_parameters" and any(
            item is None for item in (wif, p2pkh, p2sh)
        ):
            raise ConfigurationError(
                f"{path}.address is missing prefixes required by transparent derivation"
            )
        signing_sources = signing.get("verification_sources")
        if signing_sources is not None and (
            not isinstance(signing_sources, list)
            or not signing_sources
            or not all(
                isinstance(item, str) and item.strip()
                for item in signing_sources
            )
        ):
            raise ConfigurationError(
                f"{path}.transparent_signing.verification_sources must be a "
                "non-empty string list"
            )
        if signing["status"] == "supported_verified_parameters":
            required_signing_fields = (
                "format",
                "transaction_version",
                "version_group_id_hex",
                "sighash",
                "consensus_branch_id_hex",
                "script_types",
                "sighash_types",
                "max_money",
                "verification_sources",
            )
            missing = [
                field for field in required_signing_fields
                if field not in signing
            ]
            if missing:
                raise ConfigurationError(
                    f"{path}.transparent_signing is missing: "
                    f"{', '.join(missing)}"
                )
            if (
                signing["format"] != "zip243-sapling-v4"
                or signing["sighash"] != "ZIP-243"
            ):
                raise ConfigurationError(
                    f"{path}.transparent_signing format or sighash is unsupported"
                )
            if signing["transaction_version"] != 4:
                raise ConfigurationError(
                    f"{path}.transparent_signing.transaction_version must be 4"
                )
            version_group_id = _require_hex(
                signing["version_group_id_hex"],
                f"{path}.transparent_signing.version_group_id_hex",
                length=4,
            )
            if int.from_bytes(version_group_id, "big") != 0x892F2085:
                raise ConfigurationError(
                    f"{path}.transparent_signing.version_group_id_hex is not "
                    "the ZIP-243 Sapling version group"
                )
            signing_branch_id = _require_hex(
                signing["consensus_branch_id_hex"],
                f"{path}.transparent_signing.consensus_branch_id_hex",
                length=4,
            )
            if (
                not isinstance(signing.get("script_types"), list)
                or not signing["script_types"]
                or not all(
                    item in {"p2pkh"} for item in signing["script_types"]
                )
            ):
                raise ConfigurationError(
                    f"{path}.transparent_signing.script_types must contain "
                    "supported script types"
                )
            if (
                not isinstance(signing.get("sighash_types"), list)
                or signing["sighash_types"] != [1]
            ):
                raise ConfigurationError(
                    f"{path}.transparent_signing.sighash_types must be [1]"
                )
            max_money = signing.get("max_money")
            if (
                isinstance(max_money, bool)
                or not isinstance(max_money, int)
                or not 1 <= max_money <= (1 << 63) - 1
            ):
                raise ConfigurationError(
                    f"{path}.transparent_signing.max_money is invalid"
                )
            if (
                address_verification != "verified"
                or derivation["status"]
                != "supported_verified_parameters"
            ):
                raise ConfigurationError(
                    f"{path}.transparent_signing requires verified address "
                    "and BIP44 parameters"
                )
            if not signing_sources:
                raise ConfigurationError(
                    f"{path}.transparent_signing is missing verification sources"
                )

        activation_height = _optional_uint(
            sapling.get("activation_height"),
            f"{path}.sapling.activation_height",
        )
        zip212_activation_height = _optional_uint(
            sapling.get("zip212_activation_height"),
            f"{path}.sapling.zip212_activation_height",
        )
        zip212_grace_period = _optional_uint(
            sapling.get("zip212_grace_period_blocks"),
            f"{path}.sapling.zip212_grace_period_blocks",
        )
        if sapling.get("note_decryption_status") == "supported_verified_parameters":
            if (
                sapling["status"] not in {
                    "supported_verified_parameters",
                    "partial",
                }
                or activation_height is None
                or zip212_activation_height is None
                or zip212_activation_height < activation_height
                or zip212_grace_period is None
                or zip212_grace_period == 0
            ):
                raise ConfigurationError(
                    f"{path}.sapling note decryption parameters are incomplete"
                )
        zip32_coin_type = _optional_uint(
            sapling.get("zip32_coin_type"),
            f"{path}.sapling.zip32_coin_type",
        )
        if zip32_coin_type is not None and zip32_coin_type >= _HARDENED_INDEX_LIMIT:
            raise ConfigurationError(
                f"{path}.sapling.zip32_coin_type must fit a hardened ZIP32 index"
            )
        if (
            zip32_coin_type is not None
            and coin_type is not None
            and zip32_coin_type != coin_type
        ):
            raise ConfigurationError(
                f"{path}.sapling.zip32_coin_type must match the transparent "
                "BIP44 coin type"
            )
        sapling_path = sapling.get("derivation_path")
        if sapling_path is not None:
            _require_text(sapling_path, f"{path}.sapling.derivation_path")
        path_status = sapling.get("derivation_path_status")
        if path_status is not None and path_status not in {
            "supported_verified_parameters",
            "unverified",
            "unsupported",
        }:
            raise ConfigurationError(
                f"{path}.sapling.derivation_path_status is invalid"
            )
        if sapling["status"] == "supported_verified_parameters" and (
            sapling_path is None
            or path_status != "supported_verified_parameters"
        ):
            raise ConfigurationError(
                f"{path}.sapling is missing a verified ZIP32 derivation path"
            )
        if path_status == "supported_verified_parameters" and (
            zip32_coin_type is None
            or sapling_path != f"m/32'/{zip32_coin_type}'/{{account}}'"
        ):
            raise ConfigurationError(
                f"{path}.sapling.derivation_path must use the configured "
                "ZIP32 coin type and account"
            )
        for field in (
            "payment_address_hrp",
            "full_viewing_key_hrp",
            "incoming_viewing_key_hrp",
            "extended_spending_key_hrp",
            "base_full_viewing_key_hrp",
        ):
            prefix = sapling.get(field)
            if prefix is not None:
                _require_text(prefix, f"{path}.sapling.{field}")
        for field in ("consensus_branch_id_hex", "testnet_consensus_branch_id_hex"):
            sapling_branch = sapling.get(field)
            if sapling_branch is not None:
                _require_hex(
                    sapling_branch,
                    f"{path}.sapling.{field}",
                    length=4,
                )
        testnet_sapling = sapling.get("testnet")
        if testnet_sapling is not None:
            testnet_sapling = _require_mapping(
                testnet_sapling,
                f"{path}.sapling.testnet",
            )
            _optional_uint(
                testnet_sapling.get("activation_height"),
                f"{path}.sapling.testnet.activation_height",
            )
            testnet_branch = testnet_sapling.get("consensus_branch_id_hex")
            if testnet_branch is not None:
                _require_hex(
                    testnet_branch,
                    f"{path}.sapling.testnet.consensus_branch_id_hex",
                    length=4,
                )
            for field in (
                "payment_address_hrp",
                "full_viewing_key_hrp",
                "incoming_viewing_key_hrp",
                "extended_spending_key_hrp",
                "base_full_viewing_key_hrp",
            ):
                prefix = testnet_sapling.get(field)
                if prefix is not None:
                    _require_text(
                        prefix,
                        f"{path}.sapling.testnet.{field}",
                    )
        for field in ("parameter_files", "verification_sources"):
            values = sapling.get(field)
            if values is not None and (
                not isinstance(values, list)
                or not all(isinstance(item, str) and item.strip() for item in values)
            ):
                raise ConfigurationError(
                    f"{path}.sapling.{field} must be a non-empty string list"
                )
        upgrade_name = sapling.get("consensus_upgrade_name")
        if upgrade_name is not None:
            _require_text(upgrade_name, f"{path}.sapling.consensus_upgrade_name")
        compact_capability = sapling.get(
            "lightwalletd_compact_block_capability"
        )
        if compact_capability is not None and compact_capability not in {
            "verified",
            "endpoint_unverified",
            "not_configured",
            "unsupported",
        }:
            raise ConfigurationError(
                f"{path}.sapling.lightwalletd_compact_block_capability is invalid"
            )
        if sapling["status"] == "supported_verified_parameters" and (
            activation_height is None
            or zip32_coin_type is None
            or any(
                sapling.get(field) is None
                for field in (
                    "payment_address_hrp",
                    "full_viewing_key_hrp",
                    "incoming_viewing_key_hrp",
                    "extended_spending_key_hrp",
                )
            )
        ):
            raise ConfigurationError(
                f"{path}.sapling is missing verified parameters"
            )

        branch_id = value.get("branch_id_hex")
        if branch_id is not None:
            branch_bytes = _require_hex(branch_id, f"{path}.branch_id_hex", length=4)
            branch_id = int.from_bytes(branch_bytes, "big")
        if signing["status"] == "supported_verified_parameters":
            signing_branch_id = int(
                signing["consensus_branch_id_hex"],
                16,
            )
            if branch_id != signing_branch_id:
                raise ConfigurationError(
                    f"{path}.transparent_signing consensus branch id must match "
                    "the network's configured branch id"
                )

        return cls(
            coin_id=coin_id,
            network_id=network_id,
            name=coin["name"],
            symbol=coin["symbol"],
            verification=verification,
            address_verification=address_verification,
            wif_prefix=wif,
            p2pkh_prefix=p2pkh,
            p2sh_prefix=p2sh,
            bech32_hrp=hrp,
            electrum=electrum,
            bitcore=bitcore,
            lightwalletd=lightwalletd,
            transparent_derivation=derivation,
            transparent_signing=signing,
            sapling=sapling,
            xpub_headers=xpub_headers,
            xprv_headers=xprv_headers,
            branch_id=branch_id,
        )

    @property
    def electrum_servers(self):
        return list(self.electrum["servers"])

    @property
    def electrum_ports(self):
        return {
            "t": str(self.electrum["ports"].get("tcp", "")),
            "s": str(self.electrum["ports"].get("ssl", "")),
            "w": str(self.electrum["ports"].get("websocket", "")),
        }

    @property
    def bitcore_explorer(self):
        return self.bitcore.get("explorer_url")

    @property
    def bitcore_api(self):
        return self.bitcore.get("api_path")

    @property
    def bitcore_socket_path(self):
        return self.bitcore.get("socket_path")

    @property
    def lightwalletd_endpoints(self):
        return list(self.lightwalletd["endpoints"])

    @property
    def addrtype_p2pkh(self):
        return self.p2pkh_prefix

    @property
    def addrtype_p2sh(self):
        return self.p2sh_prefix


@dataclass(frozen=True)
class CoinConfig:
    coin_id: str
    name: str
    symbol: str
    networks: Mapping[str, CoinNetworkConfig]

    @classmethod
    def from_mapping(cls, value):
        value = _require_mapping(value, "coin")
        coin_id = _require_text(value.get("id"), "coin.id").lower()
        name = _require_text(value.get("name"), f"coins.{coin_id}.name")
        symbol = _require_text(value.get("symbol"), f"coins.{coin_id}.symbol")
        networks_value = _require_mapping(
            value.get("networks"), f"coins.{coin_id}.networks"
        )
        if not networks_value:
            raise ConfigurationError(f"coins.{coin_id}.networks cannot be empty")
        networks = {
            network_id: CoinNetworkConfig.from_mapping(
                coin_id,
                {"name": name, "symbol": symbol},
                network_id,
                network_value,
            )
            for network_id, network_value in networks_value.items()
        }
        return cls(coin_id, name, symbol, networks)

    def get_network(self, network_id="mainnet"):
        try:
            return self.networks[network_id]
        except KeyError as exc:
            raise ConfigurationError(
                f"coin '{self.coin_id}' has no configured network '{network_id}'"
            ) from exc


def _parse_headers(value, path):
    value = _require_mapping(value, path)
    if not value:
        raise ConfigurationError(f"{path} cannot be empty")
    headers = {}
    for key, raw in value.items():
        if not isinstance(key, str) or not isinstance(raw, str):
            raise ConfigurationError(f"{path} entries must be named hex strings")
        try:
            number = int(raw, 16)
        except ValueError as exc:
            raise ConfigurationError(f"{path}.{key} is not valid hex") from exc
        if not 0 <= number < (1 << 32):
            raise ConfigurationError(f"{path}.{key} is outside uint32")
        headers[key] = number
    return headers
