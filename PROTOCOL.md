# eggomi-meta-bridge link protocol

The keeper (the one program allowed to talk to this bridge) dials the bridge's link listener and sends
requests; the bridge answers each one. Everything the bridge observes on Messenger reaches the keeper as
journaled events the keeper pulls with a long poll and acknowledges once it has stored them. This file is
the only contract between the two programs.

## 1. Transport

- TCP, the keeper dialling. Noise `Noise_KK_25519_ChaChaPoly_SHA256`, prologue `eggomi/cah-channel/v1`,
  the keeper as initiator and the bridge as responder, both handshake payloads empty. Each side holds
  the other's static public key in advance; only the configured keeper key completes the handshake.
- Frames are a big-endian `u16` length (1..65535) followed by the body. The two handshake frames are the
  byte `0x01` followed by the Noise message. After the handshake each frame is one Noise transport
  message carrying one UTF-8 JSON object.
- The handshake and the first request must arrive within 5 seconds; a connection with no frame for
  120 seconds is closed. At most 4 connections are open at once and at most 16 requests may be queued on
  one connection (more closes it). Requests on one connection are answered in order, so the keeper keeps
  its long poll on a connection of its own.

## 2. Requests and answers

```
request  {"id": <integer>, "method": "<name>", "params": {...}}
answer   {"id": <same>, "result": <value>}
refusal  {"id": <same>, "error": {"code": "<code>", "message": "<code>"}}
```

- `id` is an integer within ±(2^53-1). `params` may be omitted or `null` for methods without parameters.
- Parameters are decoded strictly: an unknown field, a wrong type or trailing data is `bad_request`.
- A refusal carries a code and nothing else: never message text, cookies, media or upstream error
  text. An internal failure is `error` (the detail stays in the bridge's own log, without parameters).
- An answer that would not fit in one frame becomes `error`. Every method below keeps its answers
  smaller than that (events and media are chunked).
- An unknown method is `unknown_method`.

## 3. Event stream

The bridge journals every domain event with a sequence number before anything else happens to it, and
keeps it until the keeper acknowledges it. Delivery is at least once: after a lost connection the keeper
asks again from its stored cursor and may see events it already has (they carry the same `seq`).

### 3.1 Cursor and epoch

The keeper stores `(epoch, cursor)`. `epoch` is a random 32-hex string fixed when the bridge's store is
created; it changes only when the store is wiped (a new volume). When the keeper sees a different epoch
it restarts from cursor 0 and treats the bridge as new. A cursor larger than the bridge's newest
sequence number is `cursor_ahead` (a cursor from a wiped store).

### 3.2 `events.next`

```
params  {"after": <cursor>, "waitMs": 0..30000, "limit": 0..500}
result  {"epoch": "...", "events": [<event>...], "latest": <newest seq>, "more": <bool>}
```

Returns events with `seq > after`, oldest first. With `waitMs > 0` and nothing pending, it waits up to
that long for the first event and then returns (possibly an empty list). `limit` 0 means 200. The events
in one answer total at most 64,495 encoded bytes; `more` is true when events remain after the last one
returned.

An event is `{"seq": n, "kind": "...", "portal": "<conversation id>", "data": {...}}` (`portal` absent
for account-wide events). An event too large for one answer travels alone, as a stub:

```
{"seq": n, "kind": "...", "portal": "...", "size": <bytes>, "chunked": true}     with "more": true
```

### 3.3 `events.chunk`

```
params  {"seq": n, "offset": <byte offset>}
result  {"seq": n, "size": <bytes>, "offset": <offset>, "data": "<base64 of up to 32 KiB>"}
```

Returns a slice of the event's JSON encoding (exactly the object `events.next` would have carried).
The keeper requests offsets until it holds `size` bytes, parses the object and continues with
`events.next` after `seq`. An acknowledged event is `gone`; an offset past the end is `bad_request`.

### 3.4 `ack`

```
params  {"seq": n}
result  {"ok": true}
```

Deletes journaled events up to and including `seq`. The keeper sends it only after its own records and
cursor are committed. `seq` larger than the newest is `cursor_ahead`.

## 4. Events

`portal` is the remote conversation id (the id `send`, `older` and the other methods take). Message ids
(`remoteId`, `targetId`, `replyToId`, `upToId`) are remote message ids; `eventId`, `target`, `replyTo` and
`upTo` are the bridge's own stable ids for the same events, for matching an event to a later edit,
reaction or deletion when the remote id is not known yet.

| kind                   | data                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `state`                | `state` (the connector's bridge state: `UNCONFIGURED`, `CONNECTING`, `CONNECTED`, `TRANSIENT_DISCONNECT`, `BAD_CREDENTIALS`, `UNKNOWN_ERROR`, `LOGGED_OUT`), optional `error` (a short upstream code), `login`                                                                                                                                             |
| `login`                | `state`: `linked` with `id` and `name`; `failed` with `code` (the code `login.cookies` answered); `logged_out`                                                                                                                                                                                                                                             |
| `conversation`         | on creation `room`, `name`, `topic`; later one of `name`, `topic`, `avatar`                                                                                                                                                                                                                                                                                |
| `conversation_deleted` | none                                                                                                                                                                                                                                                                                                                                                       |
| `member`               | `member`, `membership` (`join`, `leave`, `invite`, `ban`), optional `displayname`                                                                                                                                                                                                                                                                          |
| `item`                 | `source` (`live` or `history`), `eventId`, `remoteId`, `sender`, `timestamp` (ms), `msgtype`, `text`; optional `fileName`, `mediaRef`, `mimeType`, `size`, `replyTo`, `replyToId`, `writeKey` (the op id, on the echo of the owner's own send). A message type the bridge does not model arrives as `msgtype` `m.notice` with `system` set to the raw type |
| `edit`                 | `target`, `targetId`, `text`, `source`                                                                                                                                                                                                                                                                                                                     |
| `reaction`             | `target`, `targetId`, `emoji`, `eventId`, `source`                                                                                                                                                                                                                                                                                                         |
| `reaction_remove`      | `eventId` (of the `reaction`)                                                                                                                                                                                                                                                                                                                              |
| `delete`               | `target`, `targetId`                                                                                                                                                                                                                                                                                                                                       |
| `read`                 | the owner read the conversation on another device: `upTo`, `upToId`, `at` (ms)                                                                                                                                                                                                                                                                             |
| `op`                   | an outbound operation settled: `opId`, `state`, optional `remoteId`, `code` (section 5.1)                                                                                                                                                                                                                                                                  |

Typing and presence are never forwarded. Read receipts of other people are not forwarded.

Reaction emoji arrive as the network sends them; the upstream code adds U+FE0F to some emoji, so the
keeper compares emoji with variation selectors removed.

## 5. Outbound operations

### 5.1 The op ledger

`send` and `react` take an `opId` chosen by the keeper (1..128 of `A-Z a-z 0-9 . _ : -`). The bridge
records the op **before** handing it to the network (the commit point), with a digest of everything it
would send. An op is then in one of four states:

- `committed`: recorded, not settled yet;
- `accepted`: the network confirmed it; `remoteId` is the message id where there is one;
- `rejected`: provably not sent (a certain failure); `code` says why (`queue_failed` when the bridge
  could not queue it, otherwise the upstream reason or `provider_refused`);
- `unknown`: it may or may not have been sent (a timeout, a lost connection, or the bridge stopped
  after the commit point: `code` `bridge_restarted`). **An op is never retried by the bridge**, and the
  keeper must not resend an unknown op under a new id without the owner deciding to.

Settlement arrives as an `op` event. Repeating a request with the same `opId` and the same content
sends nothing and answers the stored row with `duplicate: true`; the same `opId` with different content
is `op_mismatch`. A refused request (any refusal code) records nothing.

The answer to `send` and `react` is `{"op": <row>, "duplicate": <bool>}`, where a row is
`{"id", "kind", "conversation", "state", "remoteId"?, "code"?, "createdAt", "settledAt"?}` (ms
timestamps).

### 5.2 Methods

| method      | params                                                                                                                                                                                     | result                                                                | refusals                                                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `send`      | `opId`, `conversation`, `text` (1..20,000 code points, not blank), optional `replyTo` (remote message id)                                                                                  | op answer                                                             | `not_logged_in`, `unknown_conversation`, `target_gone` (reply target unknown), `op_mismatch`                                    |
| `react`     | `opId`, `conversation`, `item` (remote message id), `emoji` (a string of up to 32 bytes with no ASCII letters, spaces or controls; `null` removes the owner's newest reaction on the item) | op answer                                                             | as `send`                                                                                                                       |
| `markRead`  | `conversation`, `upTo` (remote message id)                                                                                                                                                 | `{"ok": true}`                                                        | `not_logged_in`, `unknown_conversation`, `target_gone`                                                                          |
| `older`     | `conversation`                                                                                                                                                                             | `{"queued": true}` or `{"queued": false}` (no older history to fetch) | `not_logged_in`, `unknown_conversation`, `busy` (another `older` for this conversation less than 10 seconds ago), `unsupported` |
| `reconcile` | `opId`                                                                                                                                                                                     | `{"op": <row>}`                                                       | `unknown_op`                                                                                                                    |
| `op`        | `opId`                                                                                                                                                                                     | `{"op": <row or null>}`                                               |                                                                                                                                 |

Ids (`conversation`, `item`, `replyTo`, `upTo`) are 1..256 bytes of UTF-8 with no spaces or control
characters; anything else is `bad_request`.

- **History.** Each conversation's first sync carries its newest 50 messages. `older` fetches one more
  page of 50 older messages; they arrive as `item` events with `source` `history`. Nothing older is
  fetched unless the keeper asks.
- **`reconcile`** re-checks an `unknown` op against the bridge's own message table, without touching the
  network: if the message exists, the op becomes `accepted` (and an `op` event follows). Other states
  are returned unchanged.

## 6. Media

An `item` with an attachment carries `mediaRef`. Refs starting with `d` name media the bridge has not
fetched; refs starting with `c` name bytes already in its cache.

```
media.get  params {"ref": "...", "offset": <byte offset>}
           result {"ref": "...", "size": <bytes>, "offset": <offset>, "data": "<base64 of up to 32 KiB>"}
```

The first `media.get` for a `d` ref fetches the whole item through the connector (and so through the
egress proxy) into the cache; later chunks are served from there. One fetch runs at a time. Items over
25 MiB are never fetched: `media_too_large`. A failed fetch is `media_unavailable` (the keeper may try
again later); a cached item that has since been evicted is `media_not_found`. The cache holds at most
500 MiB and evicts the least recently used items. An offset past the end is `bad_request`.

## 7. Account

### 7.1 `login.cookies`

```
params  {"sealed": {"v": 1, "epk": "<hex>", "iv": "<hex>", "aad": "<canonical JSON>", "ct": "<hex>"}}
result  {"ok": true, "login": {"id": "...", "name": "..."}}
```

The blob is sealed to this bridge's static link key by the guard (the sealer, whose static public key
the bridge is configured with), so the keeper forwards it without being able to read it. The bridge
fails closed; the checks run in this order and the first failure answers:

1. `bad_request`: no blob or malformed parameters.
2. `busy`: another login or logout is running.
3. `not_configured`: the bridge has no sealer key, instance or generation.
4. `handoff_limit`: 4 handoffs have already been opened in the last 24 hours.
5. `denied_payload` / `denied_seal`: the blob is malformed, its associated data is not exactly the
   canonical bound fields, or it does not open with the bridge's key and the sealer's key.
6. `denied_bound`: the bound fields do not name `field` `cookies`, `origin` `https://www.facebook.com`,
   `audience` (the hex of the keeper's static public key), `recipient_instance` and
   `recipient_generation` exactly as this bridge is configured.
7. `denied_replay`: the bound `grant_ref` was used before. A grant is spent here, before anything else
   can fail, and is never accepted again.
8. `denied_payload`: the plaintext is not a JSON object of exactly the cookies `datr`, `c_user`, `sb`,
   `xs` (with `datr`, `c_user` and `xs` non-empty).
9. `account_mismatch`: an account is already linked and the cookies belong to another one.
10. The login itself runs (at most 90 seconds, through the egress; it finishes even if the keeper's
    connection drops). A failure answers one of `checkpoint`, `challenge`, `consent`,
    `token_invalidated`, `rate_limited`, `account_suspended`, `timeout`, `account_mismatch`,
    `denied_payload` or `login_failed`, and is also journaled as a `login` event.

The plaintext is zeroed as soon as it is parsed. Cookie values never appear in a log line, an answer or
an event. A linked login's session lives in the bridge's database on its own volume.

### 7.2 `login.secret`

Reserved for the Messenger PIN that unlocks encrypted chat history. The pinned upstream connector has no
flow to restore history with it, so the bridge refuses every call with `unsupported` without opening
the blob: the PIN never exists in this process.

### 7.3 `logout`

```
params  {}
result  {"ok": true, "count": <logins removed>}
```

Signs the session out at Meta (removing the bridge's encrypted-chat device) and deletes the login; a
`login` event with `state` `logged_out` follows. `busy` while a login runs. Wiping the volume is the
operator's job.

## 8. `status`

```
params  {}
result  {"epoch": "...", "latest": <newest seq>, "pending": <unacknowledged events>,
         "state": "<last bridge state, STARTING before the first>", "error": "..."?,
         "login": {"id": "...", "name": "..."} | null, "version": "...", "upstream": "<commit>"}
```

## 9. Limits

| what                                | limit                                                                                        |
| ----------------------------------- | -------------------------------------------------------------------------------------------- |
| frame                               | 65,535 bytes; one answer's events 64,495 encoded bytes                                       |
| `events.next`                       | `waitMs` ≤ 30,000; `limit` ≤ 500 (default 200)                                               |
| chunk (`events.chunk`, `media.get`) | 32 KiB of raw bytes                                                                          |
| text                                | 20,000 code points                                                                           |
| ids                                 | 256 bytes; op ids 128                                                                        |
| emoji                               | 32 bytes                                                                                     |
| media                               | 25 MiB per item; 500 MiB cache                                                               |
| history                             | 50 messages per first sync and per `older` page; one `older` per conversation per 10 seconds |
| handoffs                            | 4 opened per rolling 24 hours; each grant once                                               |
| login                               | 90 seconds; media fetch 2 minutes                                                            |
| connections                         | 4 open; 16 queued requests each; 5 s to handshake and first request; 120 s idle              |

## 10. Codes

| code                                                                                                                      | meaning                                                                          |
| ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `bad_request`                                                                                                             | parameters malformed or out of range                                             |
| `unknown_method`                                                                                                          | no such method                                                                   |
| `error`                                                                                                                   | internal failure (details only in the bridge's log)                              |
| `cursor_ahead`                                                                                                            | cursor newer than the bridge's newest event: restart from 0 if the epoch changed |
| `gone`                                                                                                                    | the event was acknowledged and deleted                                           |
| `not_logged_in`                                                                                                           | no linked account                                                                |
| `unknown_conversation`                                                                                                    | the conversation id is not known to the bridge                                   |
| `target_gone`                                                                                                             | the message the request refers to is not known                                   |
| `op_mismatch`                                                                                                             | the op id was used with different content                                        |
| `unknown_op`                                                                                                              | no op with this id                                                               |
| `busy`                                                                                                                    | try again later (a login is running, or `older` too soon)                        |
| `unsupported`                                                                                                             | not available in this build                                                      |
| `media_too_large`, `media_unavailable`, `media_not_found`                                                                 | section 6                                                                        |
| `not_configured`, `handoff_limit`, `denied_payload`, `denied_seal`, `denied_bound`, `denied_replay`, `account_mismatch`   | section 7.1                                                                      |
| `checkpoint`, `challenge`, `consent`, `token_invalidated`, `rate_limited`, `account_suspended`, `timeout`, `login_failed` | the login failed at Meta (section 7.1, step 10)                                  |
