
import asyncio
from urllib.parse import urlsplit

from .clients import ElectrumClient, BitcoreClient
from .coins import (
    CoinConfig,
    ConfigurationError,
    get_coin_config as get_coin_config,
    get_coin_network as get_coin_network,
    load_coin_configs,
    set_active_network,
)


class ClientManager:

    def __init__(self, coin_configs=None):
        self.coin_configs = (
            load_coin_configs()
            if coin_configs is None
            else dict(coin_configs)
        )
        self.clients = {}
        self.protocols = {}
        self._switch_locks = {}
        self._network_configs = {}

        self.on_block_events = None
        self.on_address_events = None
        self.on_status = None

        self.ks = None

    def add(self, coin, protocol=None, network="mainnet"):
        key = coin.strip().lower()

        if key not in self.coin_configs:
            raise ConfigurationError(f"unknown coin: {coin}")

        if key in self.clients:
            if self._network_configs[key].network_id != network:
                raise ConfigurationError(
                    f"coin '{key}' is already registered for network "
                    f"'{self._network_configs[key].network_id}'"
                )
            return self.clients[key]

        coin_config = self.coin_configs[key]
        if not isinstance(coin_config, CoinConfig):
            raise ConfigurationError(f"invalid configuration for coin '{key}'")
        network_config = coin_config.get_network(network)
        self._network_configs[key] = network_config

        electrum_protocols = ["tcp", "ssl", "wss", "ws"]

        if protocol == "lightwalletd":
            if not network_config.lightwalletd_endpoints:
                raise ValueError(
                    f"Coin '{key}' has no Lightwalletd servers"
                )
            protocols = ["lightwalletd"]

        elif protocol == "bitcore":
            protocols = ["bitcore"] + electrum_protocols

        elif protocol in electrum_protocols:
            protocols = [protocol] + [
                p for p in electrum_protocols if p != protocol
            ] + ["bitcore"]

        else:
            if network_config.electrum_servers:
                protocols = electrum_protocols + ["bitcore"]
            elif network_config.bitcore_api:
                protocols = ["bitcore"] + electrum_protocols
            else:
                raise ValueError(
                    f"Coin '{key}' has no Electrum servers or Bitcore API"
                )

        self.protocols[key] = protocols
        self._switch_locks[key] = asyncio.Lock()

        client = self._create_client(
            key,
            network_config,
            protocols[0]
        )

        self.clients[key] = client

        return client

    def _create_client(self, coin, network_config, protocol):
        if protocol == "lightwalletd":
            from .clients.lightwalletd import LightwalletdClient

            servers = network_config.lightwalletd_endpoints
            if not servers:
                raise ValueError(f"Coin '{coin}' has no Lightwalletd servers")

            endpoint = urlsplit(f"//{servers[0]}")
            if not endpoint.hostname:
                raise ValueError(
                    f"Invalid Lightwalletd server for coin '{coin}'"
                )

            client = LightwalletdClient(
                endpoint.hostname,
                endpoint.port or 9067,
            )

        elif protocol in ("tcp", "ssl", "wss", "ws"):
            if not network_config.electrum_servers:
                raise ValueError(f"Coin '{coin}' has no Electrum servers")
        
            client = ElectrumClient(network_config, protocol=protocol)
        
        elif protocol == "bitcore":
            if not network_config.bitcore_api:
                raise ValueError(f"Coin '{coin}' has no Bitcore API")
        
            client = BitcoreClient(network_config)

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
        network_config = self._network_configs[coin]

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
                        network_config,
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

            network_config = self._network_configs[key]

            last_error = None

            for protocol in alternatives:
                client = None

                try:
                    client = self._create_client(
                        key,
                        network_config,
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
            return client._connected.is_set()

        if getattr(client, "protocol", None) == "lightwalletd":
            return client.connected

        return False

    def _get_protocol(self, client):
        if isinstance(client, ElectrumClient):
            return client.protocol

        if isinstance(client, BitcoreClient):
            return "bitcore"

        if getattr(client, "protocol", None) == "lightwalletd":
            return "lightwalletd"

        return None

    def get_protocol(self, coin):
        return self._get_protocol(self.get(coin))

    def set_network(self, coin, network="mainnet"):
        if coin.strip().lower() not in self.coin_configs:
            raise ConfigurationError(f"unknown coin: {coin}")
        return set_active_network(coin, network)

    def __getitem__(self, coin):
        return self.get(coin)

    def __contains__(self, coin):
        return coin.strip().lower() in self.clients

    def __len__(self):
        return len(self.clients)