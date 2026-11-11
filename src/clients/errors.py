

from typing import Optional

import grpc

"""Errors that describe a conclusive transaction rejection."""


class PermanentBroadcastRejection(Exception):
    """The network conclusively rejected this exact transaction as invalid."""


_PERMANENT_REJECTION_MARKERS = (
    "bad-txns-vin-empty",
    "bad-txns-vout-empty",
    "bad-txns-oversize",
    "bad-txns-inputvalues-outofrange",
    "bad-txns-outputvalues-outofrange",
    "bad-txns-duplicate",
    "bad-txns-prevout-null",
    "mandatory-script-verify-flag-failed",
    "non-mandatory-script-verify-flag",
    "transaction decode failed",
    "deserialize failed",
    "invalid transaction",
)


def is_permanent_rejection(error):
    message = str(error).lower()
    return any(marker in message for marker in _PERMANENT_REJECTION_MARKERS)


"""Errors raised by the asynchronous Lightwalletd client."""


class LightwalletdError(Exception):
    """Base class for Lightwalletd client errors."""


class LightwalletdConnectionError(LightwalletdError):
    """The client could not establish or use its gRPC connection."""


class LightwalletdTimeoutError(LightwalletdError, TimeoutError):
    """A connection or RPC deadline expired."""


class LightwalletdRpcError(LightwalletdError):
    """A Lightwalletd RPC returned a non-OK gRPC status."""

    def __init__(
        self,
        method: str,
        code: Optional[grpc.StatusCode],
        details: str,
    ) -> None:
        self.method = method
        self.code = code
        self.details = details
        super().__init__(f"{method} failed ({code}): {details}")


class LightwalletdBlockHashMismatchError(LightwalletdError):
    """A height fallback returned a block other than the requested hash."""

    def __init__(self, requested_hash: bytes, returned_hash: bytes) -> None:
        self.requested_hash = requested_hash
        self.returned_hash = returned_hash
        super().__init__(
            "GetBlock height fallback returned hash "
            f"{returned_hash.hex()}, expected {requested_hash.hex()}"
        )

