from .electrum import ElectrumClient as ElectrumClient
from .bitcore import BitcoreClient as BitcoreClient


def __getattr__(name):
    if name == "LightwalletdClient":
        from .lightwalletd import LightwalletdClient
        return LightwalletdClient

    if name in {
        "LightwalletdBlockHashMismatchError",
        "LightwalletdConnectionError",
        "LightwalletdError",
        "LightwalletdRpcError",
        "LightwalletdTimeoutError",
    }:
        from . import errors
        return getattr(errors, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")