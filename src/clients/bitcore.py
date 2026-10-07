
import asyncio
import json
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlencode, urlsplit, urlunsplit

IS_WEB = False

try:
    from js import JSON, Object, Uint8Array, WebSocket, fetch

    IS_WEB = True
except ModuleNotFoundError:
    import aiohttp
    import websockets


class BitcoreClient:
    """Async client for Bitcore/Insight APIs and their Socket.IO event stream.

    The client supports both:
    - Pyodide/browser environments through the JavaScript Fetch/WebSocket APIs.
    - Native Python through aiohttp and websockets.
    - Engine.IO polling as a fallback, or as an explicitly selected transport.

    Socket.IO here intentionally uses the Engine.IO v3 / Socket.IO packet format
    expected by the Bitcore-compatible explorer endpoint.
    """

    SOCKETIO_PATH = "/socket.io/?EIO=3&transport=websocket"
    SOCKETIO_EVENT_PREFIX = "42"
    ENGINEIO_OPEN_PREFIX = "0"
    ENGINEIO_PING = "2"
    ENGINEIO_PONG = "3"
    SOCKETIO_CONNECT = "40"

    def __init__(
        self,
        coin: Any,
        timeout: int = 10,
        transport: str = "auto",
    ) -> None:
        if transport not in ("auto", "websocket", "polling"):
            raise ValueError(
                "transport must be 'auto', 'websocket', or 'polling'"
            )

        self.coin: Any = coin
        self.height: int = 0
        self.base_url: Optional[str] = coin.BITCORE_API.rstrip("/") if coin.BITCORE_API else None
        self.url: Optional[str] = self.base_url  # Backward-compatible public attribute.
        self.timeout: int = timeout
        self.transport: str = transport
        self._active_transport: Optional[str] = None
        self._polling_sid: Optional[str] = None

        # HTTP/WebSocket resources.
        self.session: Any = fetch if IS_WEB else None
        self._polling_session: Any = None
        self.ws: Any = None

        # Event callbacks.
        self.on_block_events: Optional[Callable[[Dict[str, Any]], Any]] = None
        self.on_address_events: Optional[Callable[[Dict[str, Any]], Any]] = None
        self.on_status: Optional[Callable[[str], Any]] = None

        # Socket.IO state.
        self._subscribed_addresses: Set[str] = set()
        self._headers_subscribed: bool = False
        self._packet_id: int = 0

        # Connection lifecycle state.
        self._loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
        self._connected: asyncio.Event = asyncio.Event()
        self._connect_lock: asyncio.Lock = asyncio.Lock()
        self._connecting: bool = False
        self._reader_task: Optional[asyncio.Task[Any]] = None
        self._keepalive_task: Optional[asyncio.Task[Any]] = None


    # HTTP

    def _get_http_session(self) -> Any:
        """Return the browser fetch function or create the native HTTP session."""
        if IS_WEB:
            return self.session

        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={
                    "User-Agent": "BitcoreClient/1.0",
                    "Content-Type": "application/json",
                },
            )

        return self.session

    async def _request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Any:
        """Send an HTTP request and return the decoded JSON response."""
        if not self.base_url:
            raise RuntimeError("Bitcore API URL is not configured")

        url = self._build_api_url(endpoint)
        session = self._get_http_session()

        if IS_WEB:
            options = Object.fromEntries([
                ["method", method],
                ["headers", Object.fromEntries([
                    ["Content-Type", "application/json"],
                ])],
            ])

            if method != "GET" and data is not None:
                options["body"] = JSON.stringify(data)

            response = await session(url, options)

            if not response.ok:
                body = await response.text()
                raise RuntimeError(
                    f"HTTP {response.status}: {body}"
                )

            result = await response.json()
            return result.to_py()

        try:
            async with session.request(
                method,
                url,
                json=data,
            ) as response:
                body = await response.text()

                if response.status >= 400:
                    raise RuntimeError(
                        f"HTTP {response.status}: {body}"
                    )

                if not body:
                    return {}

                return json.loads(body)

        except aiohttp.ClientError as exc:
            raise ConnectionError(
                f"Bitcore API connection failed: {exc}"
            ) from exc

    async def get(self, endpoint: str) -> Any:
        """Perform a GET request."""
        return await self._request("GET", endpoint)

    async def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Any:
        """Perform a POST request."""
        return await self._request("POST", endpoint, data)

    def _build_api_url(self, endpoint: str) -> str:
        """Join an API route to its configured mount without duplicating segments."""
        if not self.base_url:
            raise RuntimeError("Bitcore API URL is not configured")

        base = urlsplit(self.base_url)
        route = urlsplit(endpoint.lstrip("/"))
        base_segments = [part for part in base.path.split("/") if part]
        route_segments = [part for part in route.path.split("/") if part]

        if (
            route_segments
            and route_segments[0] == "api"
            and base_segments
            and "api" in base_segments[-1].lower()
        ):
            route_segments = route_segments[1:]

        overlap = 0
        for length in range(
            min(len(base_segments), len(route_segments)),
            0,
            -1,
        ):
            if base_segments[-length:] == route_segments[:length]:
                overlap = length
                break

        path = "/" + "/".join(
            base_segments + route_segments[overlap:]
        )
        return urlunsplit((
            base.scheme,
            base.netloc,
            path,
            route.query,
            "",
        ))

    def _build_socketio_url(self, transport: str, sid: Optional[str] = None) -> Optional[str]:
        """Build a Socket.IO URL independently of the REST API mount path."""
        if not self.base_url:
            return None

        base = urlsplit(self.base_url)
        if base.scheme not in ("http", "https"):
            return None

        socket_path = getattr(
            self.coin,
            "BITCORE_SOCKET_PATH",
            urlsplit(self.SOCKETIO_PATH).path,
        )
        socket_path = "/" + socket_path.lstrip("/")
        params = {
            "EIO": "3",
            "transport": transport,
        }
        if sid:
            params["sid"] = sid

        scheme = "wss" if base.scheme == "https" else "ws"
        return urlunsplit((
            scheme,
            base.netloc,
            socket_path,
            urlencode(params),
            "",
        ))

    # WebSocket / Socket.IO connection

    def _build_websocket_url(self) -> Optional[str]:
        """Convert the configured API origin into its Socket.IO WebSocket URL."""
        return self._build_socketio_url("websocket")

    def _build_polling_url(self, sid: Optional[str] = None) -> Optional[str]:
        """Build an Engine.IO v3 polling URL independently of the API mount."""
        return self._build_socketio_url("polling", sid)

    async def ensure_connected(self) -> None:
        """Ensure that the Socket.IO connection is established."""
        if self._connected.is_set():
            return

        await self.connect()

    async def connect(self) -> None:
        """Serialize connection attempts and establish the configured transport."""
        async with self._connect_lock:
            if self._connected.is_set():
                return
            await self._connect()

    async def _connect(self) -> None:
        """Connect using WebSocket, falling back to Engine.IO polling if needed."""
        if self._connecting:
            return

        self._connecting = True
        self._connected.clear()

        try:
            await self._notify_status("connecting")

            if self.transport != "polling":
                websocket_url = self._build_websocket_url()
                if not websocket_url:
                    raise RuntimeError("Bitcore WebSocket URL is not configured")

                try:
                    if IS_WEB:
                        await self._connect_browser(websocket_url)
                    else:
                        await self._connect_native(websocket_url)
                    self._active_transport = "websocket"
                    return
                except Exception as exc:
                    await self._close_websocket()
                    if self.transport == "websocket":
                        raise
                    print(
                        "Bitcore WebSocket connection failed; "
                        f"trying polling: {exc}"
                    )

            await self._connect_polling()

        except Exception:
            self._connected.clear()
            await self._notify_status("disconnected")
            raise

        finally:
            self._connecting = False

    async def _close_websocket(self) -> None:
        """Close a partially established WebSocket before trying polling."""
        if self.ws is None:
            return

        try:
            if IS_WEB:
                self.ws.close()
            else:
                await self.ws.close()
        except Exception:
            pass
        finally:
            self.ws = None

    def _get_polling_session(self) -> Any:
        """Return an HTTP session that permits Engine.IO long-poll requests."""
        if IS_WEB:
            return self.session

        if self._polling_session is None or self._polling_session.closed:
            self._polling_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=None),
                headers={
                    "User-Agent": "BitcoreClient/1.0",
                },
            )

        return self._polling_session

    async def _polling_request(
        self,
        method: str,
        sid: Optional[str] = None,
        packet: Optional[str] = None,
    ) -> bytes:
        """Perform one Engine.IO polling GET or POST request."""
        url = self._build_polling_url(sid)
        if not url:
            raise RuntimeError("Bitcore polling URL is not configured")

        session = self._get_polling_session()
        if IS_WEB:
            entries = [
                ["method", method],
                ["headers", Object.fromEntries([
                    ["Content-Type", "text/plain; charset=UTF-8"],
                ])],
            ]
            if method == "POST":
                if packet is None:
                    raise ValueError("Polling POST requires a packet")
                body = packet.encode("utf-8")
                entries.append(["body", f"{len(body)}:{packet}"])

            response = await session(url, Object.fromEntries(entries))
            if not response.ok:
                body = await response.text()
                raise RuntimeError(
                    f"Polling {method} failed: HTTP {response.status}: {body}"
                )

            array_buffer = await response.arrayBuffer()
            return bytes(Uint8Array.new(array_buffer).to_py())

        headers = None
        request_data = None
        if method == "POST":
            if packet is None:
                raise ValueError("Polling POST requires a packet")
            encoded_packet = packet.encode("utf-8")
            request_data = (
                f"{len(encoded_packet)}:{packet}".encode("utf-8")
            )
            headers = {
                "Content-Type": "text/plain; charset=UTF-8",
            }

        async with session.request(
            method,
            url,
            data=request_data,
            headers=headers,
        ) as response:
            body = await response.read()
            if response.status != 200:
                raise RuntimeError(
                    f"Polling {method} failed: HTTP "
                    f"{response.status}: {body!r}"
                )
            return body

    @staticmethod
    def _decode_polling_payload(body: bytes) -> List[str]:
        """Decode Engine.IO v3 text or binary polling payloads."""
        packets: List[str] = []
        offset = 0

        if not body:
            return packets

        if body[0] == 0:
            while offset < len(body):
                if body[offset] != 0:
                    raise ValueError(
                        f"Invalid binary payload marker: {body[offset]:02x}"
                    )

                offset += 1
                digits = bytearray()
                while offset < len(body) and body[offset] != 0xFF:
                    digit = body[offset]
                    if digit > 9:
                        raise ValueError(
                            f"Invalid binary payload length digit: {digit}"
                        )
                    digits.append(ord("0") + digit)
                    offset += 1

                if offset >= len(body):
                    raise ValueError("Incomplete binary polling payload")
                if not digits:
                    raise ValueError("Missing binary packet length")

                offset += 1
                length = int(digits.decode("ascii"))
                end = offset + length
                if end > len(body):
                    raise ValueError("Incomplete binary polling packet")

                packets.append(body[offset:end].decode("utf-8"))
                offset = end

            return packets

        while offset < len(body):
            colon = body.find(b":", offset)
            if colon == -1:
                raise ValueError("Invalid text polling payload")

            length_text = body[offset:colon]
            if not length_text or not length_text.isdigit():
                raise ValueError("Invalid text polling packet length")

            length = int(length_text)
            offset = colon + 1
            end = offset + length
            if end > len(body):
                raise ValueError("Incomplete text polling packet")

            packets.append(body[offset:end].decode("utf-8"))
            offset = end

        return packets

    async def _connect_polling(self) -> None:
        """Establish Engine.IO and Socket.IO over HTTP long polling."""
        await self._establish_polling_session()
        self._connected.set()
        await self._notify_status("connected")
        self._reader_task = self._loop.create_task(self._read_polling())

    async def _establish_polling_session(self) -> None:
        """Create a fresh polling SID and restore Socket.IO subscriptions."""
        self._polling_sid = None
        packets = self._decode_polling_payload(
            await self._polling_request("GET")
        )
        if not packets or not packets[0].startswith(self.ENGINEIO_OPEN_PREFIX):
            raise RuntimeError(
                f"Expected Engine.IO open packet, got: {packets!r}"
            )

        handshake = json.loads(packets[0][1:])
        sid = handshake.get("sid")
        if not sid:
            raise RuntimeError("Engine.IO polling handshake did not include a sid")

        self._polling_sid = str(sid)
        self._active_transport = "polling"
        await self._polling_request(
            "POST",
            self._polling_sid,
            self.SOCKETIO_CONNECT,
        )

        if self._headers_subscribed:
            await self._send_header_subscriptions()

        for address in self._subscribed_addresses:
            packet = self._create_socketio_packet(
                "subscribe",
                "bitcoind/addresstxid",
                [address],
            )
            await self._send_socket_message(packet)

    async def _read_polling(self) -> None:
        """Read and dispatch packets from the Engine.IO polling transport."""
        try:
            while self._connected.is_set():
                if self._polling_sid is None:
                    try:
                        await self._establish_polling_session()
                        await self._notify_status("connected")
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        print(
                            "Bitcore polling reconnect error: "
                            f"{exc}"
                        )
                        await asyncio.sleep(2)
                    continue

                try:
                    body = await self._polling_request(
                        "GET",
                        self._polling_sid,
                    )
                    for message in self._decode_polling_payload(body):
                        if message == self.ENGINEIO_PING:
                            await self._send_socket_message(self.ENGINEIO_PONG)
                        elif message.startswith(self.SOCKETIO_EVENT_PREFIX):
                            await self._handle_socketio_event(message)
                        elif message == "1":
                            raise ConnectionError(
                                "Engine.IO polling session was closed"
                            )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    await self._notify_status("reconnecting")
                    self._polling_sid = None
                    await asyncio.sleep(2)

        except asyncio.CancelledError:
            raise

        finally:
            self._connected.clear()
            self._polling_sid = None
            await self._notify_status("disconnected")

    async def _connect_browser(self, websocket_url: str) -> None:
        """Connect using the browser WebSocket API exposed by Pyodide."""
        websocket = WebSocket.new(websocket_url)
        self.ws = websocket

        connection_future = self._loop.create_future()

        async def handle_open(_event: Any) -> None:
            self._connected.set()
            await self._notify_status("connected")

            if not connection_future.done():
                connection_future.set_result(True)

        def handle_message(event: Any) -> None:
            message = str(event.data)
            self._handle_engineio_message_sync(message)

        async def handle_close(_event: Any) -> None:
            self._connected.clear()
            await self._notify_status("disconnected")

        def handle_error(_event: Any) -> None:
            self._connected.clear()

            if not connection_future.done():
                connection_future.set_exception(
                    ConnectionError("Bitcore WebSocket connection failed")
                )

        websocket.onopen = handle_open
        websocket.onmessage = handle_message
        websocket.onclose = handle_close
        websocket.onerror = handle_error

        await asyncio.wait_for(connection_future, timeout=self.timeout)

    async def _connect_native(self, websocket_url: str) -> None:
        """Connect using the native Python websockets package."""
        self.ws = await websockets.connect(
            websocket_url,
            ping_interval=None,
            ping_timeout=None,
        )

        self._connected.set()
        await self._notify_status("connected")

        self._reader_task = self._loop.create_task(
            self._read_native_websocket()
        )

        self._start_keepalive()

    async def _read_native_websocket(self) -> None:
        """Read and dispatch incoming native WebSocket messages."""
        try:
            async for message in self.ws:
                if message.startswith(self.ENGINEIO_OPEN_PREFIX):
                    await self._send_socket_message(self.SOCKETIO_CONNECT)
                    continue

                if message.startswith(self.SOCKETIO_EVENT_PREFIX):
                    await self._handle_socketio_event(message)

                elif message == self.ENGINEIO_PING:
                    await self._send_socket_message(self.ENGINEIO_PONG)

        except asyncio.CancelledError:
            raise

        except websockets.ConnectionClosed:
            pass

        except Exception as exc:
            print(f"Bitcore WebSocket reader error: {exc}")

        finally:
            self._connected.clear()
            await self._notify_status("disconnected")

    def _handle_engineio_message_sync(self, message: str) -> None:
        """Handle browser WebSocket messages without blocking the JS callback."""
        if message == self.ENGINEIO_PING:
            self._send_socket_message_sync(self.ENGINEIO_PONG)
            return

        if message.startswith(self.ENGINEIO_OPEN_PREFIX):
            self._send_socket_message_sync(self.SOCKETIO_CONNECT)
            return

        if message.startswith(self.SOCKETIO_EVENT_PREFIX):
            self._loop.create_task(self._handle_socketio_event(message))

    async def reconnect(self) -> None:
        """Close the current connection and establish a fresh one."""
        if self._connecting:
            return

        self._connected.clear()
        await self.close()

        await self._notify_status("reconnecting")
        await asyncio.sleep(2)

        await self.connect()

    async def close(self) -> None:
        """Stop background tasks and close all client resources."""
        self._connected.clear()
        self._subscribed_addresses.clear()
        self._headers_subscribed = False
        self._polling_sid = None

        await self._cancel_task("_reader_task")
        await self._cancel_task("_keepalive_task")

        await self._close_websocket()

        if not IS_WEB and self.session is not None and not self.session.closed:
            try:
                await self.session.close()
            except Exception:
                pass

        if (
            not IS_WEB
            and self._polling_session is not None
            and not self._polling_session.closed
        ):
            try:
                await self._polling_session.close()
            except Exception:
                pass

        self.session = fetch if IS_WEB else None
        self._polling_session = None
        self._active_transport = None

    async def _cancel_task(self, attribute_name: str) -> None:
        """Cancel and await a background task stored on the client."""
        task = getattr(self, attribute_name)

        if task is None:
            return

        setattr(self, attribute_name, None)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    def _start_keepalive(self) -> None:
        """Start the native keepalive task if it is not already running."""
        if self._keepalive_task is None:
            self._keepalive_task = self._loop.create_task(
                self._keepalive_loop()
            )

    async def keepalive(self, interval: int = 25) -> None:
        """Backward-compatible entry point for the keepalive loop."""
        await self._keepalive_loop(interval)

    async def _keepalive_loop(self, interval: int = 25) -> None:
        """Send periodic Engine.IO ping frames while connected."""
        while True:
            await asyncio.sleep(interval)

            if self._connected.is_set():
                await self.ping()


    # Socket.IO protocol

    def _create_socketio_packet(self, event_name: str, *args: Any) -> str:
        """Build a Socket.IO event packet using the Bitcore packet format."""
        packet_id = self._packet_id
        self._packet_id += 1

        payload = json.dumps(
            [event_name, *args],
            separators=(",", ":"),
        )

        return f"{self.SOCKETIO_EVENT_PREFIX}{packet_id}{payload}"

    async def _send_socket_message(self, message: str) -> None:
        """Send a Socket.IO packet using the active transport."""
        if self._active_transport == "polling":
            if self._polling_sid is None:
                raise ConnectionError("Bitcore polling transport is not connected")
            await self._polling_request(
                "POST",
                self._polling_sid,
                message,
            )
            return

        if self.ws is None:
            raise ConnectionError("Bitcore WebSocket is not connected")

        if IS_WEB:
            self.ws.send(message)
        else:
            await self.ws.send(message)

    def _send_socket_message_sync(self, message: str) -> None:
        """Send a raw browser WebSocket message from a JS callback."""
        if self.ws is None:
            return

        try:
            self.ws.send(message)
        except Exception:
            pass

    async def _handle_socketio_event(self, message: str) -> None:
        """Parse and dispatch a Socket.IO event packet."""
        try:
            event = json.loads(message[2:])
            event_name = event[0] if event else None
            event_data = event[1] if len(event) > 1 else None

            if event_name == "block":
                await self._handle_block_event(event_data)

            elif event_name == "bitcoind/addresstxid":
                await self._handle_address_event(event_data)

            #Not all Bitcore API implementations send info events, so avoid relying
            #on them exclusively for chain height updates.

            #elif event_name == "info":
                #self._update_height_from_info(event_data)    

        except (TypeError, IndexError, json.JSONDecodeError) as exc:
            print(f"Bitcore Socket.IO event parse error: {exc}")

    async def _handle_block_event(self, block_hash: str) -> None:
        """Forward a new-block event to the registered callback."""
        if self.on_block_events is None:
            return

        status = await self.get("status")
        self._update_height_from_info(status)
        try:
            await self.on_block_events({
                "block": {
                    "hash": block_hash,
                }
            })
        except Exception as exc:
            print(f"Bitcore block callback error: {exc}")

    async def _handle_address_event(self, transaction: Dict[str, Any]) -> None:
        """Forward an address transaction event to the registered callback."""
        if self.on_address_events is None:
            return

        try:
            await self.on_address_events({
                "tx": transaction,
            })
        except Exception as exc:
            print(f"Bitcore transaction callback error: {exc}")

    def _update_height_from_info(self, data: Any) -> None:
        """Update the local chain height from a Bitcore info event."""
        if not isinstance(data, dict):
            return

        info = data.get("info", {})
        self.height = info.get("blocks", self.height) or 0

    async def subscribe_headers(self) -> None:
        """Subscribe to block synchronization and inventory events."""
        await self.ensure_connected()
        self._headers_subscribed = True

        await self._send_header_subscriptions()

        # HTTP status gives us the current height immediately instead of
        # waiting for the next Socket.IO info event.
        status = await self.get("status")
        self._update_height_from_info(status)

    async def _send_header_subscriptions(self) -> None:
        """Subscribe to the block events on the active transport."""
        for event_name in ("sync", "inv"):
            packet = self._create_socketio_packet(
                "subscribe",
                event_name,
            )
            await self._send_socket_message(packet)

    async def unsubscribe_headers(self) -> None:
        """Unsubscribe from block synchronization and inventory events."""
        self._headers_subscribed = False
        if not self._connected.is_set():
            return

        for event_name in ("sync", "inv"):
            packet = self._create_socketio_packet(
                "unsubscribe",
                event_name,
            )
            await self._send_socket_message(packet)

    async def subscribe_address(self, address: str) -> None:
        """Subscribe to transaction notifications for an address."""
        await self.ensure_connected()

        self._subscribed_addresses.add(address)

        packet = self._create_socketio_packet(
            "subscribe",
            "bitcoind/addresstxid",
            [address],
        )
        await self._send_socket_message(packet)

    async def unsubscribe_address(self, address: str) -> None:
        """Stop receiving transaction notifications for an address."""
        self._subscribed_addresses.discard(address)

        if not self._connected.is_set():
            return

        packet = self._create_socketio_packet(
            "unsubscribe",
            "bitcoind/addresstxid",
            [address],
        )
        await self._send_socket_message(packet)

    # Address / transaction API

    @staticmethod
    def _normalize_utxos(utxos: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Normalize Bitcore UTXOs to the common client representation."""
        return [
            {
                "tx_hash": utxo.get("tx_hash") or utxo.get("txid"),
                "tx_pos": utxo.get("tx_pos") or utxo.get("vout"),
                "value": utxo.get("value") or utxo.get("satoshis"),
            }
            for utxo in utxos or []
        ]

    def normalize_utxos(self, utxos: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Backward-compatible wrapper for UTXO normalization."""
        return self._normalize_utxos(utxos)

    async def get_balance(self, address: str) -> Dict[str, int]:
        """Return confirmed and unconfirmed balance for an address."""
        data = await self.get(f"addr/{address}")

        return {
            "confirmed": data.get("balanceSat", 0),
            "unconfirmed": data.get("unconfirmedBalanceSat", 0),
        }

    async def get_history(self, address: str, limit: Optional[int] = 10) -> List[Dict[str, Any]]:
        try:
            """Return transaction history for an address."""
            endpoint = f"txs?address={address}"
            if limit is not None:
                endpoint += f"&limit={limit}"

            result = await self.get(endpoint)
            txs = result.get("txs", {})
            return [
                {"tx_hash": tx.get("txid"), "height": tx.get("blockheight")}
                for tx in txs
            ]
        except Exception:
            return []

    async def get_listunspent(self, address: str) -> List[Dict[str, Any]]:
        """Return normalized unspent transaction outputs for an address."""
        utxos = await self.get(f"addr/{address}/utxo")
        return self._normalize_utxos(utxos)

    async def get_mempool(self, address: str) -> List[Dict[str, Any]]:
        try:
            """Return mempool transactions that involve the given address."""
            mempool = await self.get("mempool")
            related_transactions: List[Dict[str, Any]] = []

            for transaction in mempool or []:
                if self._transaction_involves_address(transaction, address):
                    related_transactions.append(transaction)

            return related_transactions
        except Exception:
            return []

    @staticmethod
    def _transaction_involves_address(transaction: Dict[str, Any], address: str) -> bool:
        """Check whether an address appears in a transaction input or output."""
        for input_data in transaction.get("vin", []):
            if address in input_data.get("addresses", []):
                return True

        for output_data in transaction.get("vout", []):
            script_pub_key = output_data.get("scriptPubKey", {})

            if address in script_pub_key.get("addresses", []):
                return True

        return False

    async def get_transaction(self, txid: str, verbose: bool = True) -> Dict[str, Any]:
        """Return a transaction by transaction ID."""
        return await self.get(f"tx/{txid}")

    async def broadcast(self, tx_hex: str) -> Any:
        """Broadcast a signed raw transaction through the Bitcore API."""
        try:
            result = await self.post(
                "tx/send",
                {"rawtx": tx_hex}
            )
            return result.get("txid")
        except Exception:
            return None

    # Unsupported Electrum-style methods

    async def estimate_fee(self, blocks: int) -> Any:
        raise NotImplementedError(
            "Bitcore does not provide a direct fee-estimation endpoint"
        )

    async def get_fee_histogram(self) -> Any:
        raise NotImplementedError(
            "Bitcore does not provide a fee histogram endpoint"
        )

    async def get_relay_fee(self) -> Any:
        raise NotImplementedError(
            "Bitcore does not provide a relay-fee endpoint"
        )

    async def get_donation_address(self) -> Any:
        raise NotImplementedError(
            "Bitcore does not provide a donation-address endpoint"
        )

    async def server_version(
        self,
        client_name: str = "Bitcore Wallet",
        protocol_version: str = "1.0",
    ) -> List[str]:
        """Return a version tuple compatible with the common client API."""
        return [client_name, protocol_version]

    async def ping(self) -> None:
        """Send an Engine.IO heartbeat frame."""
        if self.ws is None or not self._connected.is_set():
            return

        try:
            await self._send_socket_message(self.ENGINEIO_PONG)
        except Exception:
            pass

    async def _notify_status(self, status: str) -> None:
        """Safely notify the caller about a connection state change."""
        if self.on_status is None:
            return

        try:
            await self.on_status(status)
        except Exception as exc:
            print(f"Bitcore status callback error: {exc}")
