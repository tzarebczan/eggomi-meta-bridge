# eggomi-meta-bridge

A Facebook Messenger bridge for one person's Eggomi computer. It runs the Messenger connector from
[mautrix-meta](https://github.com/mautrix/meta) under mautrix-go's `bridgev2` framework, but with no
Matrix homeserver: a small "sink" takes the homeserver's place and turns what the connector does into
journaled events, and the owner's keeper reads them over an encrypted link. The keeper sends messages,
reactions and read receipts back the same way.

- One owner, one Messenger account, one process. The keeper is the only peer that can connect.
- The only way out is an HTTP CONNECT proxy (the computer's egress). The configuration that forces it is
  compiled in, not read from a file.
- Login takes cookies from a sealed handoff the keeper cannot read (PROTOCOL.md section 7.1).
- [`PROTOCOL.md`](PROTOCOL.md) is the whole contract between the bridge and the keeper.

## Source code offer (AGPL-3.0 section 13)

This program is free software under the GNU Affero General Public License, version 3
([`LICENSE`](LICENSE)). It includes mautrix-meta, which is under the same license. If you run this
program, or a modified version of it, for users who interact with it over a network, you must offer
them the corresponding source. The program reports its own version and the upstream commit in the
`status` answer so an operator can link users to the exact source of what they run.

The corresponding source is this repository plus the module versions recorded in `go.mod` and
`go.sum`, which `go mod download` fetches.

mautrix-meta's `LICENSE.exceptions` grants extra permissions to specific companies; those permissions
are not granted to anyone else by this repository.

## Upstream

`go.mod` pins `go.mau.fi/mautrix-meta` to commit `da5fbd43c1a6df36f3ea286a068184024ae5d4f6`
(2026-10-05) as a pseudo-version, and `go.sum` holds its checksum, so every build uses exactly that
tree, unmodified. `config.Upstream` repeats the commit for the `status` answer; a test checks that the
two agree.

`go.mod` also repeats upstream's `replace github.com/imroc/req/v3 => github.com/beeper/req/v3 ...`:
replace directives in a dependency's `go.mod` do not apply to the modules that import it, and the build
fails without it. Keep the two in sync when moving the pin.

At this commit the connector's web user agent claims Chrome 141. `TestUserAgentDrift` (in `config/`)
reports that version and fails when a new pin changes it, so the change gets reviewed. With
`EGGOMI_BROWSER_CHROME=<major>` it also fails when the bridge is more than one major version away from
the browser the owner signs in with.

To move the pin: `go get go.mau.fi/mautrix-meta@<commit>`, copy any changed `replace` lines from its
`go.mod`, update `config.Upstream`, then `go mod tidy` and the tests.

## Layout

```
cmd/eggomi-meta-bridge/  main: environment, keys, forced config, link listener
app/                     assembles the store, the sink and the bridgev2 bridge
sink/                    bridgev2's MatrixConnector and MatrixAPI, with no homeserver behind them
core/                    the link methods (PROTOCOL.md)
link/                    Noise KK link: listener, frames, a Go client for tests
seal/                    opens sealed handoffs
outbox/                  the event journal: sequence numbers, epoch, long-poll wait, ack
ops/                     the outbound op ledger and its commit point
media/                   capped on-disk media cache (500 MiB, 25 MiB per item)
config/                  the forced connector and bridgev2 configuration
testing/fakenet/         a fake network connector for tests
testing/harness/         the assembled program in a temp dir, for tests
e2e/                     scenario tests through bridgev2 with the fake connector
testdata/                interop vectors for the link and the seal
```

## Build

Go 1.26 or newer (tested with 1.27.3).

```
go build -ldflags "-X main.version=$(git rev-parse --short HEAD)" ./cmd/eggomi-meta-bridge
```

The binary needs cgo (SQLite).

## Run

Configuration is environment variables only; `cmd/eggomi-meta-bridge/main.go` documents each one.
Keys are files holding 64 lowercase hex characters.

| variable           |                                                                                             |
| ------------------ | ------------------------------------------------------------------------------------------- |
| `META_LINK_LISTEN` | `<ipv4>:<port>` of the link listener                                                        |
| `META_LINK_KEY`    | path of the bridge's static X25519 private key                                              |
| `META_KEEPER_PUB`  | path of the keeper's static public key                                                      |
| `META_SEALER_PUB`  | path of the sealer's static public key; without it `login.cookies` answers `not_configured` |
| `META_INSTANCE`    | the instance name a handoff must be bound to (default `meta-bridge`)                        |
| `META_GENERATION`  | the generation a handoff must be bound to (required with `META_SEALER_PUB`)                 |
| `META_PROXY`       | `http://<ipv4>:<port>` of the egress proxy (required)                                       |
| `META_DATA`        | data directory (default `/data`): `bridge.db`, `eggomi.db`, `media/`                        |
| `META_LOG`         | `info` (default), `warn` or `error`                                                         |

Anything malformed refuses to start. The Go runtime's soft memory limit defaults to 160 MiB unless
`GOMEMLIMIT` is set. The process logs JSON lines to standard error, never with request parameters,
message text or cookie values; `debug` and `trace` are refused because upstream code logs more at those
levels.

## Forced configuration

`config.Forced` builds the connector configuration and `config.Check` verifies it at every start:

- every connection goes through `META_PROXY`: `proxy_media`, `proxy_e2ee`, `proxy_messenger_lite` and
  `proxy_other` are all on; `get_proxy_from` is empty and Tor is off, so the proxy never changes and
  never comes from the network;
- typing is never sent (`send_presence_on_typing` off), and the sink drops typing and presence;
- reconnects are paced: a full reconnect at most once an hour, a forced refresh every 20 hours;
- history: the first sync of each conversation carries 50 messages; older pages are fetched only when
  the keeper asks (`older`), never by a background queue;
- media is fetched only when the keeper asks (`media.get`), never at arrival, and nothing over 25 MiB.

## Handoff binding

A cookie handoff is sealed by the sealer to the bridge's static key and must bind, in its associated
data, `field` = `cookies`, `origin` = `https://www.facebook.com`, `audience` = the hex of the keeper's
static public key, `recipient_instance` = `META_INSTANCE`, `recipient_generation` = `META_GENERATION`,
and a single-use `grant_ref`. The bridge checks all of them itself, whatever the sealer and the keeper
already checked, and refuses on the first doubt, before any network request. At most 4 handoffs are
opened per rolling 24 hours. Section 7.1 of `PROTOCOL.md` lists the checks in order.

## Behaviour of the upstream framework the sink relies on

Each is pinned by a test in `e2e/` or `core/`:

- read receipts given to `QueueMatrixEvent` are ignored unless marked ephemeral, with a
  `*event.ReceiptEventContent` pointer as content;
- `bridgev2` adds U+FE0F to some reaction emoji, so emoji must be compared without variation
  selectors;
- remote deletions and reaction removals reach the sink parsed (`RedactionEventContent` in `Parsed`,
  nothing in `Raw`);
- reaction metadata can be empty when a reaction is sent, so the sink gives reaction events ids it can
  recognise when they are later redacted;
- with no double puppeting, the owner's own actions arrive on the bot intent: a read on another device
  is a `MarkRead` on the bot intent;
- "provably not sent" is a failed message status marked certain; everything else settles `unknown`;
- `GenerateDeterministicRoomID` is called before `CreateRoom`, when the portal has no room yet; the sink
  remembers the mapping so the creation event names the remote conversation.

## Tests

```
go test ./...
```

- `cmd/eggomi-meta-bridge` `TestHermetic` runs the program with the real Messenger connector inside a
  user and network namespace (`unshare -Urn`) where only loopback exists, behind a proxy that records
  and refuses every request, and attempts a login with a sealed handoff of canary cookie values. It
  checks that every connection is a CONNECT to a Meta host through the proxy, that no canary value
  appears in the logs, the answers or the files left behind, and the process's memory. Without user
  namespaces it is skipped; set `EGGOMI_REQUIRE_HERMETIC=1` to make that a failure.
- `e2e` `TestMemoryBudget` loads 2,500 messages and a 25 MiB attachment and checks the process stays
  under 128 MiB (the deployment's cap is 192 MiB).
- `link` checks the Noise KK handshake and frames against vectors recorded from the keeper's
  implementation in `testdata/interop.json`; `TestKeeperClient` also runs the keeper's own client when
  `EGGOMI_REPO` points at a checkout of it. `testdata/gen-interop.mjs` regenerates the vectors. All
  keys and cookie values in `testdata` are test values.

## Not supported

- `login.secret` (the Messenger PIN for encrypted history): the pinned connector has no restore flow,
  so the bridge refuses it without opening it.
- Sending media, editing or deleting sent messages, typing and presence.
- More than one account.
