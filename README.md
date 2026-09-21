# st API server

Signaling for desktop and Android clients, with an end-to-end encrypted TCP
relay when direct connections and UDP hole punching cannot establish a path.

## Internet deployment

The HTTP API and TCP relay use separate listeners:

| Setting | Default | Purpose |
| --- | --- | --- |
| `BIND_ADDR` | `0.0.0.0:3000` | HTTP signaling and `/health` |
| `RELAY_BIND_ADDR` | `0.0.0.0:3001` | Raw TCP relay; `off` disables it |
| `RELAY_PUBLIC_PORT` | Relay listener port | Port clients and hosts dial externally |

Expose the API through HTTPS. Also publish the relay TCP port through the
firewall/container mapping at the API URL's hostname. An HTTP reverse proxy
alone does not expose the raw TCP relay. If the external relay port differs
from its listener port, set `RELAY_PUBLIC_PORT` to that external port.

For example, mapping public TCP port 43001 to container port 3001 requires:

```sh
docker run --rm -p 3000:3000 -p 43001:3001 \
  -e RELAY_PUBLIC_PORT=43001 ghcr.io/pulstart/api-server:0.1.2
```

`/health` reports local listener availability; a successful health check does
not prove the relay is reachable through the public firewall or proxy.
Test a connection from a separate network. Routers with restrictive NAT or
networks blocking UDP can require the TCP relay even when signaling works.

## Validation

```sh
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

The tests cover process leases, request generations, partner identity checks,
relay tickets, pairing, byte forwarding, replay rejection, and relay capacity.

## Signaling snapshot rollout (0.1.2)

Deploy this API version before client 0.12.15 and server 0.9.16. Registration
now returns a `session` snapshot with peer public keys, candidates, identities,
and pending requests from the same store lock. The host uses this response
as its signaling poll, reducing five HTTP round trips to one and removing the
need for a client-side synchronization sleep. Public keys are public X25519
material; private keys and derived session keys never leave the endpoints.

Active tunnels renew their existing process lease through `/api/heartbeat`.
Unlike registration, a heartbeat cannot create or revive a client slot.

The regression suite includes first-punch visibility and lease renewal without
replacing the request context. Real NAT traversal still requires a test between
separate networks.
