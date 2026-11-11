"""Native asynchronous gRPC client for the Zcash Light Wallet Protocol."""

import asyncio
import inspect
from collections.abc import AsyncIterator
from typing import Any, Callable, Optional

import grpc
from google.protobuf.message import Message

from .errors import (
    LightwalletdBlockHashMismatchError,
    LightwalletdConnectionError,
    LightwalletdError,
    LightwalletdRpcError,
    LightwalletdTimeoutError,
)
from .protocol import compact_formats_pb2 as compact_pb2
from .protocol import service_pb2 as pb2
from .protocol import service_pb2_grpc


class LightwalletdClient:
    """Async client for the official Lightwalletd gRPC service.

    Protobuf messages and byte fields are returned unchanged. Transaction
    inputs must be serialized bytes; no hex or byte-order conversions occur.
    """

    protocol = "lightwalletd"

    def __init__(
        self,
        host: str,
        port: int = 9067,
        *,
        tls: bool = True,
        credentials: Optional[grpc.ChannelCredentials] = None,
        connection_timeout: float = 10.0,
        rpc_timeout: float = 30.0,
    ) -> None:
        if not host or not host.strip():
            raise ValueError("host must not be empty")
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if connection_timeout <= 0 or rpc_timeout <= 0:
            raise ValueError("timeouts must be greater than zero")
        if credentials is not None and not tls:
            raise ValueError("credentials require TLS to be enabled")

        self.host = host.strip()
        self.port = port
        self.tls = tls
        self.credentials = credentials
        self.connection_timeout = connection_timeout
        self.rpc_timeout = rpc_timeout

        self._channel: Optional[grpc.aio.Channel] = None
        self._stub: Optional[service_pb2_grpc.CompactTxStreamerStub] = None
        self._connect_lock = asyncio.Lock()
        self.on_status: Optional[Callable[[str], Any]] = None

    @property
    def target(self) -> str:
        host = self.host
        if ":" in host and not (host.startswith("[") and host.endswith("]")):
            host = f"[{host}]"
        return f"{host}:{self.port}"

    @property
    def connected(self) -> bool:
        return self._channel is not None

    async def connect(self) -> None:
        """Create the gRPC channel and wait until the endpoint is ready."""
        async with self._connect_lock:
            if self.connected:
                return

            if self.tls:
                credentials = self.credentials or grpc.ssl_channel_credentials()
                channel = grpc.aio.secure_channel(self.target, credentials)
            else:
                channel = grpc.aio.insecure_channel(self.target)

            try:
                await asyncio.wait_for(
                    channel.channel_ready(),
                    timeout=self.connection_timeout,
                )
            except asyncio.CancelledError:
                await channel.close()
                raise
            except asyncio.TimeoutError as exc:
                await channel.close()
                raise LightwalletdTimeoutError(
                    f"Timed out connecting to {self.target}"
                ) from exc
            except grpc.RpcError as exc:
                await channel.close()
                raise LightwalletdConnectionError(
                    f"Could not connect to {self.target}: {exc}"
                ) from exc

            self._channel = channel
            self._stub = service_pb2_grpc.CompactTxStreamerStub(channel)
            await self._notify_status("connected")

    async def close(self) -> None:
        """Close the gRPC channel; safe to call when already disconnected."""
        channel = self._channel
        self._channel = None
        self._stub = None
        if channel is not None:
            await channel.close()
            await self._notify_status("disconnected")

    async def _notify_status(self, status: str) -> None:
        if self.on_status is None:
            return
        result = self.on_status(status)
        if inspect.isawaitable(result):
            await result

    def _require_stub(self) -> service_pb2_grpc.CompactTxStreamerStub:
        if self._stub is None:
            raise LightwalletdConnectionError(
                "Client is not connected; call connect() first"
            )
        return self._stub

    def _deadline(self, timeout: Optional[float]) -> float:
        deadline = self.rpc_timeout if timeout is None else timeout
        if deadline <= 0:
            raise ValueError("timeout must be greater than zero")
        return deadline

    @staticmethod
    def _rpc_error(method: str, error: grpc.RpcError) -> LightwalletdError:
        code_method = getattr(error, "code", None)
        code = code_method() if callable(code_method) else None
        details_method = getattr(error, "details", None)
        details = details_method() if callable(details_method) else str(error)
        if code == grpc.StatusCode.DEADLINE_EXCEEDED:
            return LightwalletdTimeoutError(
                f"{method} exceeded its RPC deadline: {details}"
            )
        return LightwalletdRpcError(method, code, details)

    async def _unary(
        self,
        method: str,
        request: Message,
        timeout: Optional[float],
    ) -> Message:
        rpc = getattr(self._require_stub(), method)
        try:
            return await rpc(request, timeout=self._deadline(timeout))
        except grpc.RpcError as exc:
            raise self._rpc_error(method, exc) from exc

    async def _stream(
        self,
        method: str,
        request: Message,
        timeout: Optional[float],
    ) -> AsyncIterator[Message]:
        rpc = getattr(self._require_stub(), method)
        call = rpc(request, timeout=self._deadline(timeout))
        try:
            async for response in call:
                yield response
        except grpc.RpcError as exc:
            raise self._rpc_error(method, exc) from exc
        finally:
            if not call.done():
                call.cancel()

    async def get_lightd_info(
        self,
        *,
        timeout: Optional[float] = None,
    ) -> pb2.LightdInfo:
        return await self._unary("GetLightdInfo", pb2.Empty(), timeout)

    async def get_latest_block(
        self,
        *,
        timeout: Optional[float] = None,
    ) -> pb2.BlockID:
        return await self._unary("GetLatestBlock", pb2.ChainSpec(), timeout)

    async def get_block(
        self,
        block: pb2.BlockID,
        *,
        timeout: Optional[float] = None,
    ) -> compact_pb2.CompactBlock:
        stub = self._require_stub()
        deadline = self._deadline(timeout)
        rpc = stub.GetBlock
        try:
            response = await rpc(block, timeout=deadline)
        except grpc.RpcError as exc:
            details = exc.details() or ""
            unsupported_hash_selector = (
                exc.code() == grpc.StatusCode.INVALID_ARGUMENT
                and "hash specifier is not yet implemented" in details.lower()
            )
            if not unsupported_hash_selector or not block.height:
                raise self._rpc_error("GetBlock", exc) from exc
        else:
            if block.hash and response.hash != block.hash:
                raise LightwalletdBlockHashMismatchError(
                    block.hash,
                    response.hash,
                )
            return response

        fallback_request = pb2.BlockID(height=block.height)
        try:
            response = await rpc(fallback_request, timeout=deadline)
        except grpc.RpcError as exc:
            raise self._rpc_error("GetBlock", exc) from exc

        if response.hash != block.hash:
            raise LightwalletdBlockHashMismatchError(
                block.hash,
                response.hash,
            )
        return response

    def get_block_range(
        self,
        block_range: pb2.BlockRange,
        *,
        timeout: Optional[float] = None,
    ) -> AsyncIterator[compact_pb2.CompactBlock]:
        return self._stream("GetBlockRange", block_range, timeout)

    async def get_transaction(
        self,
        tx_filter: pb2.TxFilter,
        *,
        timeout: Optional[float] = None,
    ) -> pb2.RawTransaction:
        return await self._unary("GetTransaction", tx_filter, timeout)

    async def send_transaction(
        self,
        transaction: pb2.RawTransaction | bytes,
        *,
        timeout: Optional[float] = None,
    ) -> pb2.SendResponse:
        request = (
            transaction
            if isinstance(transaction, pb2.RawTransaction)
            else pb2.RawTransaction(data=transaction)
        )
        return await self._unary("SendTransaction", request, timeout)

    def get_address_txids(
        self,
        address_filter: pb2.TransparentAddressBlockFilter,
        *,
        timeout: Optional[float] = None,
    ) -> AsyncIterator[pb2.RawTransaction]:
        """Call the legacy GetTaddressTxids RPC (which streams full transactions)."""
        return self._stream("GetTaddressTxids", address_filter, timeout)

    def get_address_transactions(
        self,
        address_filter: pb2.TransparentAddressBlockFilter,
        *,
        timeout: Optional[float] = None,
    ) -> AsyncIterator[pb2.RawTransaction]:
        """Stream transactions for a transparent address using the current RPC."""
        return self._stream("GetTaddressTransactions", address_filter, timeout)
