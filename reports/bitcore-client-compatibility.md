# Bitcore client compatibility

## Purpose and scope

Record compatibility findings for configured Bitcore REST and Socket.IO
endpoints, including history, transaction retrieval, and failure handling.

## Implemented functionality

The shared Bitcore client normalizes an explicit `404 Address not found` as
empty history, rejects invalid history limits and malformed response shapes
explicitly, and normalizes a missing transaction to `None`. Other HTTP failures
propagate rather than being represented as successful responses.

## Findings and compatibility status

BitcoinZ REST status, bounded history, and known transaction retrieval
succeeded; Socket.IO subscribe/unsubscribe calls were accepted. Flux REST and
Socket.IO bounded checks succeeded, but no known Flux transaction was
retrieved. Gemlink, Zclassic, Zero, and ZeroClassic REST checks returned
bounded empty histories; Socket.IO outcomes varied (HTTP 400/404 or successful
calls). KomodoClassic endpoints timed out. These do not imply all features
are Verified: per-network statuses and known-transaction evidence are in the
[historical compatibility record](coin-registry-compatibility-audit.md).

## Limitations and verification

Empty history is not proof of populated-history functionality. Socket.IO
subscription acceptance was not equivalent to observing a live notification.
Only BitcoinZ had the cited known transaction retrieval check.

Bounded probes were read-only and used ephemeral addresses. Endpoint failures
are marked Unavailable rather than attributed to the implementation. Refer to
the [historical compatibility record](coin-registry-compatibility-audit.md)
for exact statuses and test results.

## References and provenance

Endpoint declarations are in the per-coin JSON under
[`src/coins/`](../src/coins/). The original bounded REST and Socket.IO results
and test record are retained in the
[historical compatibility record](coin-registry-compatibility-audit.md).
