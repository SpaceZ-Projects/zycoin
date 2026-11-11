"""Load and validate packaged coin JSON definitions."""

import json
from contextvars import ContextVar
from pathlib import Path

from .coin_schemas import CoinConfig, ConfigurationError

_DEFINITIONS = Path(__file__).parent / "coins"
_active_network = ContextVar("zycoin_active_network", default=None)


def load_coin_configs(directory=None, *, reload=False):
    """Load every JSON definition from the configured directory."""
    root = Path(directory) if directory is not None else _DEFINITIONS
    if not root.is_dir():
        raise ConfigurationError(f"coin definition directory does not exist: {root}")
    configs = {}
    for path in sorted(root.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError(
                f"could not load coin definition {path.name}: {exc}"
            ) from exc
        config = CoinConfig.from_mapping(raw)
        if config.coin_id != path.stem.lower():
            raise ConfigurationError(
                f"{path.name} declares coin id '{config.coin_id}'"
            )
        if config.coin_id in configs:
            raise ConfigurationError(f"duplicate coin id: {config.coin_id}")
        configs[config.coin_id] = config
    if not configs:
        raise ConfigurationError(f"no coin JSON definitions found in {root}")
    return dict(configs)


def get_coin_ids():
    return tuple(sorted(load_coin_configs()))


def get_coin_config(coin_id):
    if not isinstance(coin_id, str):
        raise ConfigurationError("coin identifier must be a string")
    key = coin_id.strip().lower()
    try:
        return load_coin_configs()[key]
    except KeyError as exc:
        raise ConfigurationError(f"unknown coin: {coin_id}") from exc


def get_coin_network(coin_id, network="mainnet"):
    if not isinstance(network, str) or not network.strip():
        raise ConfigurationError("network identifier must be a non-empty string")
    return get_coin_config(coin_id).get_network(network.strip().lower())


def set_active_network(coin_id, network="mainnet"):
    config = get_coin_network(coin_id, network)
    _active_network.set(config)
    return config


def get_active_network():
    network = _active_network.get()
    if network is None:
        raise ConfigurationError(
            "no active coin network; pass a network explicitly or call "
            "set_active_network(coin_id, network)"
        )
    return network
