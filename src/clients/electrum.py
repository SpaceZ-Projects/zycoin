
import asyncio
import hashlib
import json
import ssl
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ..crypto import address_to_scripthash

IS_WEB = False

try:
    from js import WebSocket
    IS_WEB = True
except ModuleNotFoundError:
    pass


class ElectrumClient:
    """Asynchronous Electrum protocol client supporting TCP, SSL, and WebSockets.
    
    Manages connection lifecycles, JSON-RPC requests, keepalive pings, and real-time
    block/address subscriptions.
    """

    def __init__(self, coin: Any, protocol: Optional[str] = None) -> None:
        self.coin = coin
        self.height: int = 0
        self.protocol: str = protocol or ("wss" if IS_WEB else "ssl")
        self.base_url: Optional[Union[str, Tuple[str, int]]] = None
        self.url: Optional[str] = coin.BITCORE_API.rstrip("/") if coin.BITCORE_API else None

        # Transport handles
        self.ws: Optional[Any] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.reader_task: Optional[asyncio.Task] = None

        # RPC state management
        self._id: int = 0
        self._pending: Dict[int, asyncio.Future] = {}

        # Event callbacks
        self.on_block_events: Optional[Callable[[Dict[str, Any]], Any]] = None
        self.on_address_events: Optional[Callable[[Dict[str, Any]], Any]] = None
        self.on_status: Optional[Callable[[str], Any]] = None
        self._subscribed_addresses: Dict[str, str] = {}

        # Background tasks & synchronization
        self._keepalive_task: Optional[asyncio.Task] = None
        self._loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
        self._connected: asyncio.Event = asyncio.Event()
        self._connecting: bool = False

    def build_target(self, host: str) -> Union[str, Tuple[str, int]]:
        """Resolves a server host and protocol into a connection target (URL or host/port tuple)."""
        ports = self.coin.DEFAULT_PORTS
        if self.protocol == "wss":
            return f"wss://{host}:{ports['w']}"
        elif self.protocol == "ws":
            return f"ws://{host}:{ports['w']}"
        elif self.protocol == "ssl":
            return (host, int(ports["s"]))
        elif self.protocol == "tcp":
            return (host, int(ports["t"]))
        raise ValueError(f"Unsupported protocol: {self.protocol}")

    async def _benchmark_server(self, host: str, timeout: float = 5.0) -> Tuple[Union[str, Tuple[str, int]], float]:
        """Measures network latency to an individual Electrum server."""
        target = self.build_target(host)
        start = time.perf_counter()
        
        try:
            if self.protocol in ("ws", "wss"):
                ws = WebSocket.new(target)
                future: asyncio.Future = self._loop.create_future()

                def on_open(_: Any) -> None:
                    if not future.done():
                        future.set_result((time.perf_counter() - start) * 1000)

                def on_error(_: Any) -> None:
                    if not future.done():
                        future.set_exception(ConnectionError("WebSocket connection failed"))

                ws.onopen = on_open
                ws.onerror = on_error
                latency = await asyncio.wait_for(future, timeout=timeout)
                ws.close()
                return (target, latency)
            else:
                host_str, port = target
                ssl_ctx = ssl.create_default_context() if self.protocol == "ssl" else None
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host_str, port, ssl=ssl_ctx),
                    timeout=timeout
                )
                latency = (time.perf_counter() - start) * 1000
                writer.close()
                await writer.wait_closed()
                return (target, latency)

        except Exception:
            return (target, float("inf"))

    async def _select_fastest_server(self) -> Union[str, Tuple[str, int]]:
        """Pings all available servers concurrently and returns the target with the lowest latency."""
        tasks = [self._benchmark_server(host) for host in self.coin.SERVERS]
        results = await asyncio.gather(*tasks)
        results.sort(key=lambda x: x[1])
        
        target, latency = results[0]
        if latency == float("inf"):
            raise ConnectionError(f"Failed to connect to any server. Last target: {target}")

        return target

    async def connect(self) -> None:
        """Connects to the optimal (lowest latency) available Electrum server."""
        if self._connecting:
            return
        
        self._connecting = True
        self._connected.clear()
        
        try:
            self.base_url = await self._select_fastest_server()
            if self.on_status:
                await self.on_status("connecting")

            if self.protocol in ("ws", "wss"):
                await self._connect_websocket()
            else:
                await self._connect_tcp()

            if not self._keepalive_task or self._keepalive_task.done():
                self._keepalive_task = self._loop.create_task(self._keepalive_loop())

        finally:
            self._connecting = False

    async def ensure_connected(self) -> None:
        """Ensures the client has an active connection, triggering a connection attempt if necessary."""
        if self._connected.is_set():
            return
        if not self._connecting:
            self._loop.create_task(self.connect())
        await self._connected.wait()

    async def _connect_websocket(self) -> None:
        """Establishes and configures a WebSocket connection for browser-based environments."""
        self.ws = WebSocket.new(self.base_url)
        future: asyncio.Future = self._loop.create_future()

        async def on_open(_: Any) -> None:
            self._connected.set()
            if self.on_status:
                await self.on_status("connected")
            if not future.done():
                future.set_result(True)

        def on_error(_: Any) -> None:
            self._connected.clear()
            if not future.done():
                future.set_exception(ConnectionError("WebSocket connection failed"))

        async def on_message(event: Any) -> None:
            await self._dispatch_message(event.data)

        async def on_close(_: Any) -> None:
            self._connected.clear()
            if self.on_status:
                await self.on_status("disconnected")

        self.ws.onopen = on_open
        self.ws.onerror = on_error
        self.ws.onmessage = on_message
        self.ws.onclose = on_close

        await future

    async def _connect_tcp(self) -> None:
        """Establishes a TCP or SSL connection socket."""
        try:
            host, port = self.base_url  # type: ignore
            ssl_ctx = ssl.create_default_context() if self.protocol == "ssl" else None
            self.reader, self.writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
            
            self._connected.set()
            if self.on_status:
                await self.on_status("connected")
            
            self.reader_task = self._loop.create_task(self._tcp_reader_loop())

        except Exception as e:
            self._connected.clear()
            raise e

    async def _tcp_reader_loop(self) -> None:
        """Continuously reads line-delimited JSON-RPC frames over TCP/SSL."""
        try:
            while self.reader:
                line = await self.reader.readline()
                if not line:
                    break

                try:
                    await self._dispatch_message(line.decode().strip())
                except Exception as exc:
                    print(f"TCP message handling error: {exc}")

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"TCP reader error: {exc}")

        self._connected.clear()
        if self.on_status:
            await self.on_status("disconnected")

    async def reconnect(self) -> None:
        """Closes the current socket state and re-establishes connection."""
        if self._connecting:
            return

        self._connected.clear()
        await self.close()
        
        if self.on_status:
            await self.on_status("reconnecting")

        await asyncio.sleep(2)
        await self.connect()

    async def close(self) -> None:
        """Closes all active socket connections and cancels pending futures."""
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
            self.ws = None

        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
            self.writer = None

        self.reader = None

        if self.reader_task and not self.reader_task.done():
            self.reader_task.cancel()

        if self.on_status:
            try:
                await self.on_status("disconnected")
            except Exception:
                pass

        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError("Connection closed"))
        self._pending.clear()

    async def _dispatch_message(self, raw: str) -> None:
        """Parses incoming JSON-RPC messages and routes responses or server notifications."""
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return

        try:
            # Handle RPC responses matching request IDs
            if "id" in msg:
                fut = self._pending.pop(msg["id"], None)
                if fut and not fut.done():
                    if msg.get("error"):
                        fut.set_exception(Exception(str(msg["error"])))
                    else:
                        fut.set_result(msg.get("result"))
            
            # Handle unsolicited server notifications / subscriptions
            else:
                method = msg.get("method")
                if method == "blockchain.headers.subscribe":
                    if self.on_block_events:
                        self.height = msg["params"][0]["height"]
                        header_hex = msg["params"][0]["hex"]
                        self._loop.create_task(self._handle_block_header(header_hex))

                elif method == "blockchain.scripthash.subscribe":
                    if self.on_address_events:
                        scripthash = msg["params"][0]
                        address = self._subscribed_addresses.get(scripthash)
                        if address:
                            self._loop.create_task(self._handle_scripthash_notification(address))

        except Exception as exc:
            print(f"Notification handling error: {exc}")

    async def _handle_block_header(self, header_hex: str) -> None:
        """Decodes a block header and invokes the block event callback."""
        header = bytes.fromhex(header_hex)
        blockhash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
        data = {"block": {"hash": blockhash}}
        await self.on_block_events(data)

    async def _handle_scripthash_notification(self, address: str) -> None:
        """Fetches pending transactions for an updated address script hash."""
        mempool = await self.get_mempool(address)
        txids = {tx["tx_hash"]: tx for tx in mempool}
        for txid in txids:
            data = {"tx": {"address": address, "txid": txid}}
            await self.on_address_events(data)

    async def send(self, method: str, params: Optional[List[Any]] = None) -> Any:
        """Sends a JSON-RPC request to the connected Electrum server and awaits the response."""
        await self.ensure_connected()

        if params is None:
            params = []

        self._id += 1
        req_id = self._id

        request = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }

        future = self._loop.create_future()
        self._pending[req_id] = future

        raw = json.dumps(request)

        if self.protocol in ("ws", "wss"):
            self.ws.send(raw)
        else:
            if not self.writer:
                raise ConnectionError("TCP writer not ready")
            self.writer.write((raw + "\n").encode())
            await self.writer.drain()

        return await future

    async def _keepalive_loop(self, interval: int = 30) -> None:
        """Periodically pings the server to keep the connection alive."""
        try:
            while True:
                await asyncio.sleep(interval)
                if self._connected.is_set():
                    try:
                        await self.ping()
                    except Exception:
                        pass
        except asyncio.CancelledError:
            pass

    # Electrum JSON-RPC API Methods

    async def subscribe_headers(self) -> Dict[str, Any]:
        """Subscribes to block header notifications."""
        response = await self.send("blockchain.headers.subscribe")
        self.height = response["height"]
        return response

    async def unsubscribe_headers(self) -> Any:
        """Unsubscribes from block header notifications."""
        return await self.send("blockchain.headers.unsubscribe")

    async def subscribe_address(self, address: str) -> Any:
        """Subscribes to updates for a specific cryptocurrency address."""
        sh = address_to_scripthash(address)
        self._subscribed_addresses[sh] = address
        return await self.send("blockchain.scripthash.subscribe", [sh])

    async def unsubscribe_address(self, address: str) -> Any:
        """Unsubscribes from updates for a specific address."""
        sh = address_to_scripthash(address)
        self._subscribed_addresses.pop(sh, None)
        return await self.send("blockchain.scripthash.unsubscribe", [sh])

    async def get_balance(self, address: str) -> Dict[str, Any]:
        """Gets the confirmed and unconfirmed balance for an address."""
        sh = address_to_scripthash(address)
        return await self.send("blockchain.scripthash.get_balance", [sh])

    async def get_history(self, address: str) -> List[Dict[str, Any]]:
        """Gets the transaction history for an address."""
        sh = address_to_scripthash(address)
        return await self.send("blockchain.scripthash.get_history", [sh])

    async def get_listunspent(self, address: str) -> List[Dict[str, Any]]:
        """Gets unspent transaction outputs (UTXOs) for an address."""
        sh = address_to_scripthash(address)
        return await self.send("blockchain.scripthash.listunspent", [sh])

    async def get_mempool(self, address: str) -> List[Dict[str, Any]]:
        """Gets unconfirmed mempool transactions for an address."""
        sh = address_to_scripthash(address)
        return await self.send("blockchain.scripthash.get_mempool", [sh])

    async def get_transaction(self, txid: str, verbose: bool = True) -> Any:
        """Retrieves raw or verbose transaction data by transaction hash."""
        return await self.send("blockchain.transaction.get", [txid, verbose])

    async def broadcast(self, tx_hex: str) -> Any:
        """Broadcasts a raw signed transaction hex to the network."""
        return await self.send("blockchain.transaction.broadcast", [tx_hex])

    async def estimate_fee(self, blocks: int) -> Any:
        """Estimates the transaction fee per kilobyte for a given target block confirmation count."""
        return await self.send("blockchain.estimatefee", [blocks])

    async def get_fee_histogram(self) -> Any:
        """Retrieves the mempool fee histogram."""
        return await self.send("mempool.get_fee_histogram")

    async def get_relay_fee(self) -> Any:
        """Retrieves the minimum relay fee enforced by the server."""
        return await self.send("blockchain.relayfee")

    async def get_donation_address(self) -> Any:
        """Retrieves the server donation address, if supported."""
        return await self.send("server.donation_address")

    async def server_version(self, client_name: str = "Electrum Client", protocol_version: str = "1.4") -> Any:
        """Negotiates protocol and client version with the server."""
        return await self.send("server.version", [client_name, protocol_version])

    async def ping(self) -> Any:
        """Sends a keepalive ping to the server."""
        return await self.send("server.ping")