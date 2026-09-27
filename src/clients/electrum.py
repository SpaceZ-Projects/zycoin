
import time
import json
import asyncio
import hashlib

from ..crypto import address_to_scripthash

is_web = False

try:
    from js import WebSocket
    is_web = True
except ModuleNotFoundError:
    import ssl


class ElectrumClient:
    def __init__(self, coin, protocol=None):

        self.coin = coin
        self.protocol = protocol
        self.url = None

        self.ws = None
        self.reader = None
        self.writer = None
        self.reader_task = None

        self._id = 0
        self._pending = {}

        self.on_notification = None
        self.on_status = None
        self._subscribed_addresses = {}

        self._keepalive_task = None
        self._loop = asyncio.get_running_loop()
        self._connected = asyncio.Event()
        self._connecting = False

        if self.protocol is None:
            self.protocol = "wss" if is_web else "ssl"


    def build_target(self, host):
        ports = self.coin.DEFAULT_PORTS
        if self.protocol == "wss":
            return f"wss://{host}:{ports['w']}"
        elif self.protocol == "ws":
            return f"ws://{host}:{ports['w']}"
        elif self.protocol == "ssl":
            return (host, int(ports["s"]))
        elif self.protocol == "tcp":
            return (host, int(ports["t"]))
        raise Exception("Unsupported protocol")
    

    async def _measure_server(self, host, timeout=5):
        target = self.build_target(host)
        start = time.perf_counter()
        try:
            if self.protocol in ("ws", "wss"):
                ws = WebSocket.new(target)
                future = self._loop.create_future()

                def on_open(_):
                    if not future.done():
                        future.set_result((time.perf_counter() - start) * 1000)

                def on_error(_):
                    if not future.done():
                        future.set_exception(Exception("Connection failed"))
                ws.onopen = on_open
                ws.onerror = on_error
                latency = await asyncio.wait_for(future, timeout=timeout)
                ws.close()
                return (target, latency)
            else:
                host, port = target
                ssl_ctx = ssl.create_default_context() if self.protocol == "ssl" else None
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_ctx),
                    timeout=timeout
                )
                latency = (time.perf_counter() - start) * 1000
                writer.close()
                await writer.wait_closed()
                return (target, latency)

        except Exception:
            return (target, float("inf"))
        

    async def get_fastest_server(self):
        tasks = [
            self._measure_server(host)
            for host in self.coin.SERVERS
        ]
        results = await asyncio.gather(*tasks)
        results.sort(key=lambda x: x[1])
        target, latency = results[0]
        if latency == float("inf"):
            raise Exception(f"Failed to connect : {target}")

        return target


    async def connect(self):
        if self._connecting:
            return
        self._connecting = True
        self._connected.clear()
        try:
            self.url = await self.get_fastest_server()
            if self.on_status:
                await self.on_status("connecting")
            if self.protocol in ("ws", "wss"):
                await self._connect_websocket()
            else:
                await self._connect_tcp()
            if not self._keepalive_task:
                self._keepalive_task = self._loop.create_task(self.keepalive())

        finally:
            self._connecting = False


    async def ensure_connected(self):
        if self._connected.is_set():
            return
        if not self._connecting:
            self._loop.create_task(self.connect())
        await self._connected.wait()


    async def _connect_websocket(self):
        self.ws = WebSocket.new(self.url)
        future = self._loop.create_future()

        async def on_open(_):
            self._connected.set()
            if self.on_status:
                await self.on_status("connected")
            if not future.done():
                future.set_result(True)

        def on_error(_):
            self._connected.clear()
            if not future.done():
                future.set_exception(Exception("WebSocket failed"))

        async def on_message(event):
            await self._handle_message(event.data)

        async def on_close(_):
            self._connected.clear()
            if self.on_status:
                await self.on_status("disconnected")

        self.ws.onopen = on_open
        self.ws.onerror = on_error
        self.ws.onmessage = on_message
        self.ws.onclose = on_close

        await future


    async def _connect_tcp(self):
        try:
            host, port = self.url
            ssl_ctx = ssl.create_default_context() if self.protocol == "ssl" else None
            self.reader, self.writer = await asyncio.open_connection(
                host, port, ssl=ssl_ctx
            )
            self._connected.set()
            if self.on_status:
                await self.on_status("connected")
            self.reader_task = self._loop.create_task(self._tcp_reader_loop())

        except Exception as e:
            self._connected.clear()
            raise e
        

    async def _tcp_reader_loop(self):
        try:
            while True:
                line = await self.reader.readline()
                if not line:
                    break

                try:
                    await self._handle_message(line.decode().strip())
                except Exception as exc:
                    print(f"TCP message handling error: {exc}")
                    continue

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"TCP reader error: {exc}")

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
        if self.ws:
            try:
                self.ws.close()
            except:
                pass
            self.ws = None

        if self.writer:
            try:
                self.writer.close()
            except:
                pass
            self.writer = None

        self.reader = None

        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(Exception("Connection closed"))
        self._pending.clear()


    async def _handle_message(self, raw):
        try:
            msg = json.loads(raw)
        except Exception:
            return

        try:
            if "id" in msg:
                fut = self._pending.pop(msg["id"], None)
                if fut:
                    if msg.get("error"):
                        fut.set_exception(Exception(str(msg["error"])))
                    else:
                        fut.set_result(msg.get("result"))
            else:
                if self.on_notification:
                    if msg.get("method") == "blockchain.headers.subscribe":
                        header_hex = msg["params"][0]["hex"]
                        self._loop.create_task(self._fetch_block(header_hex))
                    elif msg.get("method") == "blockchain.scripthash.subscribe":
                        scripthash = msg["params"][0]
                        address = self._subscribed_addresses.get(scripthash)
                        if address:
                            self._loop.create_task(self._fetch_txs(address))

        except Exception as exc:
            print(f"Electrum notification handling error: {exc}")


    async def _fetch_block(self, header_hex):
        header = bytes.fromhex(header_hex)
        blockhash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
        data = {"block":{"hash":blockhash}}
        await self.on_notification(data)


    async def _fetch_txs(self, address):
        mempool = await self.get_mempool(address)
        txids = {tx["tx_hash"]: tx for tx in mempool}
        for txid in txids:
            data = {"tx":{"address":address,"txid":txid}}
            await self.on_notification(data)


    async def send(self, method, params=None):
        await self.ensure_connected()

        if params is None:
            params = []

        self._id += 1
        req_id = self._id

        request = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params
        }

        future = self._loop.create_future()
        self._pending[req_id] = future

        raw = json.dumps(request)

        if self.protocol in ("ws", "wss"):
            self.ws.send(raw)
        else:
            if not self.writer:
                raise Exception("TCP writer not ready")
            self.writer.write((raw + "\n").encode())
            await self.writer.drain()

        return await future


    async def keepalive(self, interval=30):
        while True:
            await asyncio.sleep(interval)
            if self._connected.is_set():
                try:
                    await self.ping()
                except:
                    pass



    async def subscribe_headers(self):
        return await self.send("blockchain.headers.subscribe")

    async def unsubscribe_headers(self):
        return await self.send("blockchain.headers.unsubscribe")

    async def subscribe_address(self, address):
        sh = address_to_scripthash(address)
        self._subscribed_addresses[sh] = address
        return await self.send("blockchain.scripthash.subscribe", [sh])

    async def unsubscribe_address(self, address):
        sh = address_to_scripthash(address)
        self._subscribed_addresses.pop(sh, None)
        return await self.send("blockchain.scripthash.unsubscribe", [sh])

    async def get_balance(self, address):
        sh = address_to_scripthash(address)
        return await self.send("blockchain.scripthash.get_balance", [sh])

    async def get_history(self, address, limit=None):
        sh = address_to_scripthash(address)
        return await self.send("blockchain.scripthash.get_history", [sh])

    async def get_listunspent(self, address):
        sh = address_to_scripthash(address)
        return await self.send("blockchain.scripthash.listunspent", [sh])

    async def get_mempool(self, address):
        sh = address_to_scripthash(address)
        return await self.send("blockchain.scripthash.get_mempool", [sh])

    async def get_transaction(self, txid, verbose=True):
        return await self.send("blockchain.transaction.get", [txid, verbose])

    async def broadcast(self, tx_hex):
        return await self.send("blockchain.transaction.broadcast", [tx_hex])

    async def estimate_fee(self, blocks):
        return await self.send("blockchain.estimatefee", [blocks])
    
    async def get_fee_histogram(self):
        return await self.send("mempool.get_fee_histogram")

    async def get_relay_fee(self):
        return await self.send("blockchain.relayfee")

    async def get_donation_address(self):
        return await self.send("server.donation_address")
    
    async def server_version(self, client_name="Electrum Web Wallet", protocol_version="1.4"):
        return await self.send("server.version", [client_name, protocol_version])
    
    async def ping(self):
        return await self.send("server.ping")