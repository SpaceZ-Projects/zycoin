# ZyCoin

ZyCoin is a Python library for coin-aware wallet primitives and asynchronous
blockchain clients. It discovers coin and network settings from JSON
configurations, allowing compatible additions without separate coin-specific
implementation modules.

## Capabilities

- Password-free BIP-39-based BIP-44 transparent and Sapling ZIP32 derivation,
  address generation, and explicit encrypted key-record import/export.
- Shared Sapling ZIP32 viewing-key derivation, compact-output scanning, note
  trial decryption, nullifier derivation, and commitment-tree witnesses, with
  coin-specific support gated by verification evidence.
- Asynchronous Electrum, Bitcore REST/Socket.IO, and Lightwalletd clients.
- Offline transparent transaction construction and signing for explicitly
  verified configurations; transaction broadcasting is not provided.

Sapling transaction proving and signing are not implemented. Lightwalletd
positions remain endpoint-derived rather than consensus-authenticated, and
BitcoinZ Sapling spending remains gated. See the reports index for the
historical verification evidence and current status classifications.

## Installation

Python 3.10 or later is required:

```sh
python -m pip install zycoin
```

## Documentation and reports

- [Documentation index](docs/README.md) — installation, usage, derivation,
  clients, transparent transactions, Sapling, and security limitations.
- [Reports index](reports/README.md) — chronological technical reports and
  verification history.

The package uses synthetic examples only in its documentation. Never expose a
recovery phrase or private key in logs, source control, or support requests.
