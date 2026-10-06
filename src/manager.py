
import asyncio
from .clients import ElectrumClient, BitcoreClient
from . import constants


class ClientManager:

    def __init__(self):
        self.clients = {}
        self.protocols = {}
        self._switch_locks = {}

        self.on_block_events = None
        self.on_address_events = None
        self.on_status = None

        self.ks = None

    def add(self, coin, protocol=None):
        key = coin.strip().lower()

        if key not in constants.COINS:
            raise ValueError(f"Unknown coin: {coin}")

        if key in self.clients:
            return self.clients[key]

        coin_class = constants.COINS[key]

        electrum_protocols = ["tcp", "ssl", "wss"]

        if protocol == "bitcore":
            protocols = ["bitcore"] + electrum_protocols

        elif protocol in electrum_protocols:
            protocols = [protocol] + [
                p for p in electrum_protocols if p != protocol
            ] + ["bitcore"]

        else:
            if coin_class.SERVERS:
                protocols = electrum_protocols + ["bitcore"]
            elif coin_class.BITCORE_API:
                protocols = ["bitcore"] + electrum_protocols
            else:
                raise ValueError(
                    f"Coin '{key}' has no Electrum servers or Bitcore API"
                )

        self.protocols[key] = protocols
        self._switch_locks[key] = asyncio.Lock()

        client = self._create_client(
            key,
            coin_class,
            protocols[0]
        )

        self.clients[key] = client

        return client

    def _create_client(self, coin, coin_class, protocol):
        if protocol in ("tcp", "ssl", "wss"):
            if not coin_class.SERVERS:
                raise ValueError(f"Coin '{coin}' has no Electrum servers")

            client = ElectrumClient(coin_class, protocol=protocol)

        elif protocol == "bitcore":
            if not coin_class.BITCORE_API:
                raise ValueError(f"Coin '{coin}' has no Bitcore API")

            client = BitcoreClient(coin_class)

        else:
            raise ValueError(f"Unknown protocol: {protocol}")

        client.on_status = lambda status, coin=coin: (
            self._on_status(coin, status)
        )

        client.on_block_events = lambda data, coin=coin: (
            self._on_notification(coin, data)
        )

        client.on_address_events = lambda data, coin=coin: (
            self._on_notification(coin, data)
        )

        return client

    async def _on_status(self, coin, status):
        if self.on_status:
            data = {
                "coin": coin,
                "status": status,
            }
            await self.on_status(data)

    async def _on_notification(self, coin, data):
        if "block" in data:
            data["block"]["coin"] = coin

            if self.on_block_events:
                await self.on_block_events(data)

        elif "tx" in data:
            data["tx"]["coin"] = coin

            if self.on_address_events:
                await self.on_address_events(data)

    def get(self, coin):
        key = coin.strip().lower()

        if key not in self.clients:
            raise ValueError(
                f"Coin is not registered: {coin}"
            )

        return self.clients[key]

    async def connect(self, coin):
        key = coin.strip().lower()

        if key not in self.clients:
            raise ValueError(
                f"Coin is not registered: {coin}"
            )

        async with self._switch_locks[key]:
            return await self._connect_with_fallback(key)

    async def _connect_with_fallback(self, coin):
        protocols = self.protocols[coin]
        coin_class = constants.COINS[coin]

        current = self.clients.get(coin)
        current_protocol = self._get_protocol(current)

        ordered = protocols.copy()

        if current_protocol in ordered:
            ordered.remove(current_protocol)
            ordered.insert(0, current_protocol)

        last_error = None

        for protocol in ordered:
            try:
                if self._get_protocol(current) == protocol:
                    client = current
                else:
                    client = self._create_client(
                        coin,
                        coin_class,
                        protocol
                    )

                await client.connect()

                self.clients[coin] = client

                return client

            except Exception as e:
                last_error = e

                try:
                    await client.close()
                except Exception:
                    pass

        raise ConnectionError(
            f"Unable to connect to {coin} using "
            f"{', '.join(ordered)}"
        ) from last_error

    async def connect_all(self):
        if not self.clients:
            return

        await asyncio.gather(
            *(
                self._connect_client(coin)
                for coin in self.clients
            )
        )

    async def _connect_client(self, coin):
        try:
            await self.connect(coin)

        except Exception as e:
            await self._on_status(
                coin,
                f"connection_failed: {e}"
            )

    async def switch(self, coin):
        key = coin.strip().lower()

        if key not in self.clients:
            raise ValueError(
                f"Coin is not registered: {coin}"
            )

        async with self._switch_locks[key]:
            current = self.clients[key]
            current_protocol = self._get_protocol(current)

            protocols = self.protocols[key]

            alternatives = [
                protocol
                for protocol in protocols
                if protocol != current_protocol
            ]

            if not alternatives:
                raise ConnectionError(
                    f"No alternative protocol available for {key}"
                )

            coin_class = constants.COINS[key]

            last_error = None

            for protocol in alternatives:
                client = None

                try:
                    client = self._create_client(
                        key,
                        coin_class,
                        protocol
                    )

                    await client.connect()

                    old_client = self.clients[key]
                    self.clients[key] = client

                    try:
                        await old_client.close()
                    except Exception:
                        pass

                    return client

                except Exception as e:
                    last_error = e

                    if client:
                        try:
                            await client.close()
                        except Exception:
                            pass

            raise ConnectionError(
                f"Unable to switch {key} from "
                f"{current_protocol}"
            ) from last_error

    async def reconnect(self, coin):
        key = coin.strip().lower()

        async with self._switch_locks[key]:
            client = self.clients[key]

            try:
                await client.close()
            except Exception:
                pass

            return await self._connect_with_fallback(key)

    async def disconnect(self, coin):
        client = self.get(coin)
        await client.close()

    async def disconnect_all(self):
        for client in self.clients.values():
            await client.close()

    def is_connected(self, coin=None):
        if coin is None:
            return any(
                self.is_connected(key)
                for key in self.clients
            )

        client = self.get(coin)

        if isinstance(client, ElectrumClient):
            return client._connected.is_set()

        if isinstance(client, BitcoreClient):
            return (
                client.session is not None
                and not client.session.closed
            )

        return False

    def _get_protocol(self, client):
        if isinstance(client, ElectrumClient):
            return client.protocol

        if isinstance(client, BitcoreClient):
            return "bitcore"

        return None

    def get_protocol(self, coin):
        return self._get_protocol(self.get(coin))

    def set_network(self, coin):
        constants.set_coin(coin)

    def __getitem__(self, coin):
        return self.get(coin)

    def __contains__(self, coin):
        return coin.strip().lower() in self.clients

    def __len__(self):
        return len(self.clients)