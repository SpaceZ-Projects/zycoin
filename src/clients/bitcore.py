
import json
import asyncio

is_web = False

try:
    from js import fetch, WebSocket, Object, JSON
    is_web = True
except ModuleNotFoundError:
    import aiohttp
    import websockets


class BitcoreClient:
    def __init__(self, coin, timeout=10):

        self.coin = coin
        self.height = 0
        self.url = coin.BITCORE_API.rstrip("/") if coin.BITCORE_API else None
        self.timeout = timeout
        self.session = None
        self.ws = None

        self.on_block_events = None
        self.on_address_events = None
        self.on_status = None

        self._subscribed_addresses = set()
        self._packet_id = 0

        self._loop = asyncio.get_running_loop()
        self._connected = asyncio.Event()
        self._connecting = False
        self._reader_task = None
        self._keepalive_task = None

        if is_web:
            self.session = fetch

    def _get_session(self):
        if is_web:
            return self.session

        if self.session is None or self.session.closed:
            import aiohttp
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={
                    "User-Agent": "BitcoreClient/1.0",
                    "Content-Type": "application/json",
                },
            )
        return self.session

    def _build_socket_url(self):
        if not self.url:
            return None
        if self.url.startswith("https://"):
            return "wss://" + self.url[8:] + "/socket.io/?EIO=3&transport=websocket"
        if self.url.startswith("http://"):
            return "ws://" + self.url[7:] + "/socket.io/?EIO=3&transport=websocket"
        return None


    async def ensure_connected(self):
        if self._connected.is_set():
            return

        if not self._connecting:
            self._loop.create_task(self.connect())

        await self._connected.wait()


    async def connect(self):
        if self._connecting or self._connected.is_set():
            return

        self._connecting = True
        self._connected.clear()

        try:
            url = self._build_socket_url()

            if not url:
                return

            if self.on_status:
                await self.on_status("connecting")

            if is_web:
                await self._connect_web(url)
            else:
                await self._connect_native(url)

        except Exception as e:
            self._connected.clear()

            if self.on_status:
                await self.on_status("disconnected")

            print("WebSocket connection error:", e)

        finally:
            self._connecting = False


    async def _connect_web(self, url):
        websocket = WebSocket.new(url)
        self.ws = websocket

        future = self._loop.create_future()

        async def on_open(event):
            self._connected.set()

            if self.on_status:
                await self.on_status("connected")

            if not future.done():
                future.set_result(True)

        def on_message(event):
            message = str(event.data)

            if message == "2":
                try:
                    self.ws.send("3")
                except Exception:
                    pass
                return

            if message.startswith("0"):
                try:
                    self.ws.send("40")
                except Exception:
                    pass
                return

            if message.startswith("42"):
                self._loop.create_task(self._handle_message(message))

        async def on_close(event):
            self._connected.clear()

            if self.on_status:
                await self.on_status("disconnected")

        def on_error(event):
            self._connected.clear()

            if not future.done():
                future.set_exception(
                    Exception("WebSocket connection failed")
                )

        self.ws.onopen = on_open
        self.ws.onmessage = on_message
        self.ws.onclose = on_close
        self.ws.onerror = on_error

        await future

    async def _connect_native(self, url):
        self.ws = await websockets.connect(
            url,
            ping_interval=None,
            ping_timeout=None,
        )

        self._connected.set()

        if self.on_status:
            await self.on_status("connected")

        self._reader_task = self._loop.create_task(
            self._read_websocket()
        )

        if not self._keepalive_task:
            self._keepalive_task = self._loop.create_task(
                self.keepalive()
            )

    async def _read_websocket(self):
        try:
            async for message in self.ws:

                if message.startswith("0"):
                    await self.ws.send("40")
                    continue

                if message.startswith("42"):
                    await self._handle_message(message)

        except asyncio.CancelledError:
            raise

        except websockets.ConnectionClosed:
            pass

        except Exception as e:
            print("WebSocket reader error:", e)

        finally:
            self._connected.clear()

            if self.on_status:
                await self.on_status("disconnected")


    async def reconnect(self):
        if self._connecting:
            return

        self._connected.clear()
        await self.close()
        if self.on_status:
            await self.on_status("reconnecting")
        await asyncio.sleep(2)
        await self.connect()

    async def close(self):
        self._connected.clear()
        self._subscribed_addresses.clear()

        if self._reader_task:
            self._reader_task.cancel()

            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

            self._reader_task = None

        if self._keepalive_task:
            self._keepalive_task.cancel()

            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

            self._keepalive_task = None

        if self.ws and not is_web:
            try:
                await self.ws.close()
            except Exception:
                pass

            self.ws = None

        if (
            not is_web
            and self.session is not None
            and not self.session.closed
        ):
            await self.session.close()

        self.session = None


    async def send(self, method, endpoint, data=None):
        endpoint = endpoint.lstrip("/")
        url = f"{self.url}/{endpoint}"
        session = self._get_session()

        if is_web:
            if method == "GET":
                options = {
                    "method": method,
                    "headers": {
                        "Content-Type": "application/json",
                    },
                }
            else:
                options = Object.fromEntries([
                    ["method", "POST"],
                    ["headers", Object.fromEntries([
                        ["Content-Type", "application/json"]
                    ])],
                    ["body", JSON.stringify(data)]
                ])

            response = await session(
                url,
                options,
            )
            if not response.ok:
                body = await response.text()
                raise Exception(
                    f"HTTP Error {response.status}: {body}"
                )

            return (await response.json()).to_py()
        try:
            async with session.request(
                method,
                url,
                json=data if data is not None else None,
            ) as response:
                body = await response.text()
                if response.status >= 400:
                    raise Exception(
                        f"HTTP Error {response.status}: {body}"
                    )
                if not body:
                    return {}
                return json.loads(body)

        except aiohttp.ClientError as e:
            raise Exception(
                f"Connection Error: {e}"
            ) from e

    def normalize_utxos(self, utxos):
        normalized = []
        for u in utxos:
            normalized.append({
                "tx_hash": u.get("tx_hash") or u.get("txid"),
                "tx_pos": u.get("tx_pos") or u.get("vout"),
                "value": u.get("value") or u.get("satoshis"),
            })
        return normalized

    async def get(self, endpoint):
        return await self.send("GET", endpoint)

    async def post(self, endpoint, data=None):
        return await self.send("POST", endpoint, data)


    async def keepalive(self, interval=25):
        while True:
            await asyncio.sleep(interval)
            if not self._connected.is_set():
                continue
            await self.ping()


    async def _handle_message(self, message):
        try:
            event = json.loads(message[2:])
            event_name = event[0]

            if event_name == "block":
                blockhash = event[1] if len(event) > 1 else {}
                if self.on_block_events:
                    data = {"block":{"hash":blockhash}}
                    try:
                        await self.on_block_events(data)
                    except Exception as exc:
                        print(f"Bitcore block callback error: {exc}")

            elif event_name == "bitcoind/addresstxid":
                address = event[1] if len(event) > 1 else {}
                if self.on_address_events:
                    data = {"tx": address}
                    try:
                        await self.on_address_events(data)
                    except Exception as exc:
                        print(f"Bitcore tx callback error: {exc}")

            elif event_name == "info":
                data = event[1] if len(event) > 1 else {}
                info = data.get("info", {})
                blocks = info.get("blocks", 0)
                self.height = blocks

        except (TypeError, IndexError, json.JSONDecodeError) as e:
            print("EVENT PARSE ERROR:", e)


    def _socketio_packet(self, event, *args):
        packet_id = self._packet_id
        self._packet_id += 1

        return f"42{packet_id}" + json.dumps([event, *args], separators=(",", ":"))
    

    async def subscribe_headers(self):
        await self.ensure_connected()
        for event in ("sync", "inv"):
            message = self._socketio_packet("subscribe", event)
            if is_web:
                self.ws.send(message)
            else:
                await self.ws.send(message)

            data = await self.get(f"api/status")
            info = data.get("info", {})
            blocks = info.get("blocks", 0)
            self.height = blocks
            
    async def unsubscribe_headers(self):
        for event in ("sync", "inv"):
            message = self._socketio_packet("unsubscribe", event)
            if is_web:
                self.ws.send(message)
            else:
                await self.ws.send(message)

    async def subscribe_address(self, address):
        self._subscribed_addresses.add(address)
        event = "bitcoind/addresstxid"
        message = self._socketio_packet("subscribe", event, [address])
        if is_web:
            self.ws.send(message)
        else:
            await self.ws.send(message)

    async def unsubscribe_address(self, address):
        self._subscribed_addresses.discard(address)
        event = "bitcoind/addresstxid"
        message = self._socketio_packet("unsubscribe", event, [address])
        if is_web:
            self.ws.send(message)
        else:
            await self.ws.send(message)        
            
    async def get_balance(self, address):
        addr = await self.get(f"api/addr/{address}")
        return {
            "confirmed":addr.get("balanceSat"),
            "unconfirmed":addr.get("unconfirmedBalanceSat")
        }

    async def get_history(self, address, limit=10):
        endpoint = f"api/addr/{address}/txs"
        if limit is not None:
            endpoint += f"?limit={limit}"
        return await self.get(endpoint)

    async def get_listunspent(self, address):
        utxos = await self.get(f"api/addr/{address}/utxo")
        return self.normalize_utxos(utxos)

    async def get_mempool(self, address):
        mempool = await self.get("api/mempool")
        related = []
        for tx in mempool:
            found = False
            for vin in tx.get("vin", []):
                if address in vin.get("addresses", []):
                    found = True
                    break
            if not found:
                for vout in tx.get("vout", []):
                    script_pub_key = vout.get("scriptPubKey", {})
                    if address in script_pub_key.get("addresses", []):
                        found = True
                        break
            if found:
                related.append(tx)
        return related

    async def get_transaction(self, txid, verbose=True):
        return await self.get(f"api/tx/{txid}")

    async def broadcast(self, tx_hex):
        if is_web:
            data = Object.fromEntries([("rawtx", tx_hex)])
        else:
            data = {"rawtx": tx_hex}
        return await self.post("api/tx/send", data)

    async def estimate_fee(self, blocks):
        raise NotImplementedError("Bitcore does not support fee estimation endpoints directly")

    async def get_fee_histogram(self):
        raise NotImplementedError("Bitcore does not support fee histograms")

    async def get_relay_fee(self):
        raise NotImplementedError("Bitcore does not support relay fee queries")

    async def get_donation_address(self):
        raise NotImplementedError("Bitcore does not support donation addresses")

    async def server_version(self, client_name="Bitcore Wallet", protocol_version="1.0"):
        return [client_name, protocol_version]

    async def ping(self):
        try:
            await self.ws.send("3")
        except Exception:
            pass