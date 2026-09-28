# zycoin

Python client library for BitcoinZ and related Zcoin-family blockchain networks.

This package exposes lightweight async clients for Electrum and Bitcore-compatible APIs, plus wallet, key, and transaction helpers used to interact with BitcoinZ networks. It is designed for developers who want to query blockchain data, monitor address activity, broadcast transactions, or build wallet tooling around the BTCZ ecosystem.

## Features

- Async connection management for Electrum servers and Bitcore APIs
- Address, transaction, balance, mempool, and UTXO queries
- Header and address subscription support
- Support for BitcoinZ, Zero, Zclassic, and Flux networks
- Wallet/key primitives and mnemonic support
- Simple client manager for registering and managing multiple coins

## Installation

```bash
pip install zycoin
```

## Quick start

```python
import asyncio
from zycoin.manager import ClientManager

async def on_status(status):
    print("status:", status)

async def on_notification(message):
    print("notification:", message)

async def main():
    manager = ClientManager()
    manager.on_status = on_status
    manager.on_block_events = on_notification
    

    client = manager.add("btcz", "bitcore")
    await manager.connect("btcz")

    await client.subscribe_address("t1Rci9gRmkJZ22vH7dToFe2Up6TpZypgimH")
    print(await client.get_balance("t1Rci9gRmkJZ22vH7dToFe2Up6TpZypgimH"))

    await manager.disconnect("btcz")

asyncio.run(main())
```

## Using the Electrum client directly

```python
import asyncio
from zycoin.constants import BitcoinZ
from zycoin.clients import ElectrumClient

async def main():
    client = ElectrumClient(BitcoinZ, protocol="ssl")
    client.on_status = lambda status: print("status:", status)

    await client.connect()
    print(await client.server_version())
    print(await client.get_balance("t1Rci9gRmkJZ22vH7dToFe2Up6TpZypgimH"))
    await client.close()

asyncio.run(main())
```

## Using the Bitcore client directly

```python
import asyncio
from zycoin.constants import BitcoinZ
from zycoin.clients import BitcoreClient

async def main():
    client = BitcoreClient(BitcoinZ)
    client.on_status = lambda status: print("status:", status)

    await client.connect()
    print(await client.get_history("t1Rci9gRmkJZ22vH7dToFe2Up6TpZypgimH", limit=5))
    await client.close()

asyncio.run(main())
```

## Managing several coins

```python
import asyncio
from zycoin.manager import ClientManager

async def main():
    manager = ClientManager()
    manager.add("btcz", "bitcore")
    manager.add("zcl")
    manager.add("zer")
    manager.add("flux")

    await manager.connect_all()
    print({coin: manager[coin].coin.NAME for coin in manager.clients})

    await manager.disconnect_all()

asyncio.run(main())
```

## Available networks

The following coin definitions are included:

- `btcz` — BitcoinZ
- `flux` — Flux
- `zcl` — Zclassic
- `zer` — Zero
- `zerc` — ZeroClassic

## Notes

- The library uses async IO throughout.
- For Electrum connections, it selects the fastest reachable server automatically.
- For Bitcore connections, it communicates with the explorer's WebSocket and REST API.

## License

MIT
