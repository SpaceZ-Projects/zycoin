
import asyncio
from .clients import ElectrumClient, BitcoreClient
from . import constants


class ClientManager:

    def __init__(self):
        self.clients = {}

        self.on_block_events = None
        self.on_address_events = None
        self.on_status = None

        self.ks = None

    def add(self, coin, protocol = None):
        key = coin.strip().lower()

        if key not in constants.COINS:
            raise ValueError(f"Unknown coin: {coin}")

        if key in self.clients:
            return self.clients[key]

        coin_class = constants.COINS[key]
        
        if protocol == "bitcore":
            client = BitcoreClient(coin_class)
        elif coin_class.SERVERS:
            client = ElectrumClient(coin_class, protocol=protocol)
        elif coin_class.BITCORE_API:
            client = BitcoreClient(coin_class)
        else:
            raise ValueError(
                f"Coin '{key}' has no Electrum servers or Bitcore API")
        
        client.on_status = lambda status, coin=key: (
            self._on_status(coin, status)
        )

        client.on_block_events = lambda data, coin=key: (
            self._on_notification(coin, data)
        )

        client.on_address_events = lambda data, coin=key: (
            self._on_notification(coin, data)
        )

        self.clients[key] = client

        return client

    async def _on_status(self, coin, status):
        if self.on_status:
            data = {"coin": coin, "status": status}
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
        client = self.get(coin)
        await client.connect()
        return client

    async def connect_all(self):
        if not self.clients:
            return

        await asyncio.gather(
            *(
                self._connect_client(client)
                for client in self.clients.values()
            )
        )

    async def _connect_client(self, client):
        await client.connect()

    async def disconnect(self, coin):
        client = self.get(coin)
        await client.close()
            
    async def disconnect_all(self):
        for client in self.clients.values():
            await client.close()

    def is_connected(self, coin=None):
        if not coin and self.clients:
            return True
        client = self.get(coin)

        if isinstance(client, ElectrumClient):
            return client._connected.is_set()

        if isinstance(client, BitcoreClient):
            return (
                client.session is not None
                and not client.session.closed
            )

        return False

    def set_network(self, coin):
        constants.set_coin(coin)
    
    def __getitem__(self, coin):
        return self.get(coin)

    def __contains__(self, coin):
        return coin.strip().lower() in self.clients

    def __len__(self):
        return len(self.clients)