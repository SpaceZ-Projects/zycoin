# Sapling ZIP32 key derivation

## Purpose and scope

Record Sapling ZIP32 key derivation, the supported network paths, and the
security gate that keeps unverified coin paths from becoming wallet defaults.

## Implemented functionality

The shared ZIP32 implementation derives master and child extended spending
keys, viewing-key children, and the Sapling key components used by the wallet.
The same BIP-39 seed can feed the independent transparent and Sapling branches.
Wallet construction requires verified network derivation parameters.

## Verification and compatibility status

Automated tests match upstream `sapling_zip32.json` vectors for the master,
`m/1`, `m/1/2'`, a non-hardened viewing child, IVK, OVK, `ak`, `nk`, and
internal key components. The Zcash mainnet account path
`m/32'/133'/{account}'` is configured and exercised. The BitcoinZ candidate
`m/32'/177'/{account}'` remains Unverified and gated; both the wallet factory
and direct construction reject it. ZIP32 implementation correctness does not
prove every coin's path.

## Limitations

BitcoinZ Sapling spending remains disabled because its account path is not
verified. Deriving keys is not proof of note spendability or support for
transaction construction, proving, or signing.

## Sources and verification record

The upstream ZIP32 vector source is
[zcash-test-vectors sapling_zip32.json](https://github.com/zcash/zcash-test-vectors/blob/master/test-vectors/json/sapling_zip32.json).
Detailed component statuses and recorded test results are in the
[historical compatibility record](coin-registry-compatibility-audit.md).
