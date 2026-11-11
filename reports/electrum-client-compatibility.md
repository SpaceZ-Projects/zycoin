# Electrum client compatibility

## Purpose and scope

Summarize Electrum transport and RPC compatibility checks for configured
endpoints, while distinguishing client implementation evidence from endpoint
availability.

## Implemented functionality

The shared client supports TCP, SSL, WebSocket, and secure WebSocket transports
where configured. Native WS/WSS transport was added using the declared
`websockets` dependency; manager selection includes WS fallback. Local-server
tests cover version negotiation, subscriptions, history, transaction
retrieval, cancellation cleanup, and close behavior.

## Findings and status

BitcoinZ endpoints answered version/RPC checks over TCP, SSL, and WSS; bounded
history and known-transaction retrieval worked over SSL. Plain WS failed on
the configured port while WSS succeeded. Flux's `electrumx.runonflux.io`
answered over TCP and supported tested version/header/subscription/history
calls; other tested transports/hosts were unavailable. Other configured
networks were Unsupported or Unavailable as detailed in the
[network table](coin-registry-compatibility-audit.md).
An unreachable public endpoint is not evidence of a shared-client defect.

## Limitations and verification

Empty histories from generated unused addresses verify response handling, not
populated account history. Subscription requests were accepted on some
endpoints, but live notification delivery was not observed. BTCZ servers
returned `-32601` for remote unsubscribe RPCs; the client suppresses local
notifications instead of sending unsupported unsubscribe methods.

The historical bounded probes used read-only requests and a known public
BitcoinZ transaction ID. Exact test-suite results and transport findings are
preserved in the [historical record](coin-registry-compatibility-audit.md).

## References and provenance

Endpoint declarations are in the per-coin JSON under
[`src/coins/`](../src/coins/). The historical record contains the bounded
probe scope, network-by-network results, and Python 3.10.11 test count.
