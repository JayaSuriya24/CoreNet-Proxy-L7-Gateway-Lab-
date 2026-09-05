# CoreNet-Proxy

A native Node.js **Layer 7 reverse proxy and load balancer**, built to make core
network infrastructure concepts observable rather than abstract: TCP accept,
TLS 1.3 termination, ALPN, SNI, HTTP/2 multiplexing, DNS resolution of upstream
targets, L7 routing, and Round-Robin balancing.

**Zero external dependencies.** Only `http`, `http2`, `tls`, `fs`, `dns`, `crypto`, `path`.

---

## 1. System Architecture Overview

The single idea the whole project is built around: **the cryptographic edge is
one hop.** The client speaks TLS 1.3 + HTTP/2 to exactly one process. That
process is the only thing in the system that owns a private key, the only thing
that parses TLS records, and the only thing that understands HTTP/2 framing.
Behind it, the origin fleet speaks boring plaintext HTTP/1.1 on loopback.

That asymmetry is what a real edge buys you: certificate management, protocol
upgrades, and connection concurrency all become one team's problem instead of
every service's problem.

```
                          ══ PUBLIC / UNTRUSTED ══
   ┌──────────┐
   │  curl /  │  1. DNS: corenet.local ──▶ 127.0.0.1
   │ browser  │  2. TCP 3-way handshake ──▶ :8443
   └────┬─────┘  3. TLS 1.3 ClientHello  { SNI: corenet.local, ALPN: h2, http/1.1 }
        │
        │  ░░░░░ ENCRYPTED · TLS 1.3 · AES-256-GCM · 1-RTT ░░░░░
        │
        │        ONE TCP connection carrying N multiplexed HTTP/2 streams
        │        ┌── stream #1  GET /api/users ──┐
        ├────────┼── stream #3  GET /api/orders ─┤
        │        ├── stream #5  GET /static/a.png┤
        │        └── stream #7  POST /api/carts ─┘
        ▼
┌───────────────────────────────────────────────────────────────────────┐
│  CoreNet-Proxy  ::  gateway.js  ::  https://0.0.0.0:8443              │
│                                                                       │
│  L4  server.on('connection')       🔗 TCP accepted, 0 bytes decrypted │
│  L5  SNICallback(servername)       🏷️  cleartext SNI → cert selection  │
│  L5  server.on('secureConnection') 🔐 TLS 1.3 handshake COMPLETE      │
│  L6  socket.alpnProtocol           🤝 ALPN vote → "h2"                │
│  ──────────── ▼ ▼ ▼  T E R M I N A T I O N   P O I N T  ▼ ▼ ▼ ─────── │
│  L7  server.on('session')          🧵 h2 session + SETTINGS preface   │
│  L7  server.on('stream')           📬 HEADERS frame → stream opened   │
│  L7  route table (path/host/hdr)   🔎 inspect :method :path :authority│
│  L7  RoundRobinPool.next()         ⚖️  cursor = (cursor + 1) % N      │
│      + active /__health probing    🩺 unhealthy targets evicted       │
│      + header hygiene              ✂️  strip :pseudo + hop-by-hop      │
│      + X-Forwarded-* injection     📎 the origin's only view of TLS   │
└──────────────────────────┬────────────────────────────────────────────┘
                           │
                           │  ▓▓▓ PLAINTEXT HTTP/1.1 ▓▓▓
                           │  keep-alive http.Agent, loopback only
                           │
        ══ PRIVATE / TRUSTED (127.0.0.1, no TLS, no certs, no HTTP/2) ══
                           │
      ┌────────────┬───────┴────┬─────────────┬──────────────┬───────────────┐
      ▼            ▼            ▼             ▼              ▼
 ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────┐ ┌─────────────┐
 │api-alpha │ │api-bravo │ │api-charlie│ │static-delta  │ │static-echo  │
 │  :9001   │ │  :9002   │ │   :9003   │ │    :9101     │ │   :9102     │
 └──────────┘ └──────────┘ └───────────┘ └──────────────┘ └─────────────┘
      └────── pool: api (round-robin) ───┘ └─ pool: static (round-robin) ─┘
```

### Why each layer exists

| Layer | Mechanism | What it actually buys you |
|---|---|---|
| L4 | `server.on('connection')` | The TCP handshake completes before *any* crypto. Logged here so you can see the gap between "socket accepted" and "bytes readable". |
| L5 | `SNICallback` | The client's DNS name arrives **in cleartext** inside ClientHello. This is the hinge between DNS and TLS, and why one IP can serve many certificates. |
| L5 | `secureConnection` | Handshake done. This is the **termination point**: ciphertext stops, plaintext begins. |
| L6 | `ALPNProtocols: ['h2','http/1.1']` | Protocol negotiation happens *inside* the TLS handshake, so choosing HTTP/2 costs zero extra round trips. |
| L7 | `server.on('stream')` | Each HEADERS frame opens an independent stream. N streams, one socket, one handshake. |
| L7 | route table | Path, `:authority`, and arbitrary headers are all readable only *because* we decrypted. This is the definition of Layer 7. |
| L7 | `RoundRobinPool` | `cursor = (cursor + 1) % N`, plus health skipping. The algorithm is trivial; the health and retry logic around it is the real engineering. |

### Two kinds of connection reuse, deliberately contrasted

- **Client → gateway:** HTTP/2 multiplexing. Many *streams* on one TCP connection.
- **Gateway → origin:** a keep-alive `http.Agent`. Many *sequential requests* on a pool of warm TCP connections.

Both eliminate handshake cost; only the first eliminates head-of-line blocking.
The logs print `socket REUSED from keep-alive pool` vs `newly established` so
you can watch the second one working.

---

## 2. Prerequisites & Local Setup

**Requirements:** Node.js ≥ 18 (verified on v26.5.0), OpenSSL, and a `curl`
built with nghttp2 (check with `curl --version | grep -i http2`).

### Generate the self-signed TLS certificate

From inside `network-core-proxy/`:

```bash
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 365 \
  -keyout key.pem -out cert.pem \
  -subj "/C=IN/ST=Tamil Nadu/L=Chennai/O=CoreNet Labs/OU=Edge Gateway/CN=corenet.local" \
  -addext "subjectAltName=DNS:corenet.local,DNS:api.corenet.local,DNS:static.corenet.local,DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"
```

Flag by flag:

| Flag | Why |
|---|---|
| `-x509` | Emit a self-signed certificate, not a CSR. No CA in the loop. |
| `-nodes` | "No DES" — leave the private key unencrypted so Node can read it without a passphrase prompt. |
| `-newkey rsa:2048` | Generate key and cert in one shot. |
| `-days 365` | Validity window. |
| `-addext "subjectAltName=..."` | **Not optional.** Every modern client ignores CN and validates against SAN. Omit this and even `curl` will complain about the name. |
| `-addext "extendedKeyUsage=serverAuth"` | Marks the cert as a TLS *server* cert. |

Verify what you produced:

```bash
openssl x509 -in cert.pem -noout -subject -dates -ext subjectAltName
```

> **Note on the key exchange:** the RSA key here signs the handshake; it does
> not encrypt the session key. TLS 1.3 removed RSA key transport entirely — the
> session key always comes from an ephemeral ECDHE exchange (X25519 by default).
> That is why TLS 1.3 has forward secrecy by construction.

`.gitignore` already excludes `*.pem`. Never commit a private key.

### Optional: make the DNS step real

```bash
echo "127.0.0.1 corenet.local api.corenet.local static.corenet.local" | sudo tee -a /etc/hosts
```

If you would rather not touch `/etc/hosts`, every command below has a
`--resolve` form that does the same mapping inside curl only.

### Run it

```bash
node gateway.js          # backends + gateway in one process
node gateway.js --quiet  # suppress the architecture logs
node gateway.js --no-backends   # gateway only (point it at your own origins)
```

Useful environment overrides: `GATEWAY_PORT`, `MIN_TLS`, `MAX_CONCURRENT_STREAMS`,
`UPSTREAM_TIMEOUT_MS`, `HEALTH_INTERVAL_MS`, `NO_COLOR`.

---

## 3. The Code

[`gateway.js`](gateway.js) — a single, fully-commented file, laid out in eight sections:

| Section | Contents |
|---|---|
| 0 | Configuration, backend topology, and the L7 route table |
| 1 | The explanatory logger (emoji + OSI-band colouring + `c#N s#M` correlation tags) |
| 2 | Mock plaintext HTTP/1.1 origins, with `?delay`, `?fail`, `?size`, `/__toggle` |
| 3 | Boot-time DNS resolution of upstream target names |
| 4 | `RoundRobinPool` + active health checking |
| 5 | Route matching and header hygiene (pseudo-header + hop-by-hop stripping) |
| 6 | The proxy data path: piping, retries, cancellation, timeouts |
| 7 | The edge: TLS 1.3 termination, ALPN, HTTP/2 session and stream lifecycle |
| 8 | Bootstrap and graceful shutdown |

Two subtleties in there that are easy to get wrong and worth reading closely:

1. **Pseudo-header stripping.** Node's HTTP/2 compatibility layer leaves
   `:method`, `:path`, `:scheme`, `:authority` sitting in `req.headers`. A `:`
   is not a legal HTTP/1.1 field-name character, so forwarding them raises
   `ERR_INVALID_HTTP_TOKEN`. See `buildUpstreamHeaders()`.
2. **Hop-by-hop stripping, in both directions.** The mock origins deliberately
   send `connection: keep-alive` back. Writing that onto an HTTP/2 stream
   raises `ERR_HTTP2_INVALID_CONNECTION_HEADERS`. See `buildDownstreamHeaders()`.

---

## 4. Step-by-Step Verification Guide

Run `node gateway.js` in one terminal and these in another. Watch both.

### 4.1 — DNS mapping, TLS 1.3, and ALPN in one command

```bash
curl -vk --http2 --resolve corenet.local:8443:127.0.0.1 \
  https://corenet.local:8443/api/users
```

`--resolve HOST:PORT:ADDR` overrides DNS inside curl, so you are exercising the
same name→address step a resolver would, without editing `/etc/hosts`.

**Look for these exact lines:**

```
* Added corenet.local:8443:127.0.0.1 to DNS cache        ← DNS mapping installed
*   Trying 127.0.0.1:8443...                             ← name resolved to address
* ALPN: curl offers h2,http/1.1                          ← client's protocol list
* SSL connection using TLSv1.3 / AEAD-AES256-GCM-SHA384  ← TLS 1.3 + AEAD cipher
* ALPN: server accepted h2                               ← the gateway chose HTTP/2
*  subject: ...CN=corenet.local                          ← your self-signed cert
* using HTTP/2
< HTTP/2 200
< x-corenet-backend: api-alpha                           ← which origin served it
< x-corenet-route: path:/api                             ← which L7 rule matched
```

Reading the handshake as **1-RTT**: in TLS 1.3 the client sends its ClientHello
*with* a key share already attached. The server replies ServerHello + key share
+ EncryptedExtensions (carrying the ALPN result) + Certificate + Finished — and
the client can send application data immediately after its own Finished. One
round trip. In curl's trace this shows as `TLSv1.3 (OUT), TLS handshake, Client
hello` followed by the server flight and then straight into `TLSv1.3 (OUT), TLS
app data` — with **no** second `Client hello`/`ServerKeyExchange` pair, which is
exactly what a TLS 1.2 2-RTT handshake would show.

`-k` is required because the certificate is self-signed. To validate properly
instead, trust your own cert: `curl --cacert cert.pem --resolve ... https://corenet.local:8443/api/users`.

The response body echoes what the origin was told about a TLS session it never
participated in:

```json
"originProtocol": "HTTP/1.1 (no TLS on this hop)",
"forwarded": { "x-forwarded-proto": "https", "x-forwarded-tls": "TLSv1.3", "x-forwarded-alpn": "h2" }
```

### 4.2 — Confirm the TLS 1.3 floor is real

```bash
curl -k --tlsv1.2 --tls-max 1.2 https://localhost:8443/api/users
```

Expected — a hard rejection, not a downgrade:

```
curl: (35) ... tlsv1 alert protocol version
```

Gateway side: `🔥 L5-TLS  TLS handshake FAILED: ... (client and server found no common ground)`

Restart with `MIN_TLS=TLSv1.2 node gateway.js` and rerun to watch the same
client succeed and negotiate `TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384`.

### 4.3 — Round-Robin load balancing

```bash
for i in $(seq 1 6); do
  curl -sk --http2 https://localhost:8443/api/users | grep servedBy
done
```

Verified output — a strict rotation with no repeats inside a lap:

```
"servedBy": "api-bravo",
"servedBy": "api-charlie",
"servedBy": "api-alpha",
"servedBy": "api-bravo",
"servedBy": "api-charlie",
"servedBy": "api-alpha",
```

Gateway log: `⚖️ L7-LB  Round-Robin selected api-charlie(127.0.0.1:9003) (cursor now 0/3)`

### 4.4 — Layer 7 routing: path, virtual host, and header

```bash
# path prefix          → static pool
curl -sk --http2 https://localhost:8443/static/logo.png | grep pool

# :authority / vhost   → static pool
curl -sk --http2 --resolve static.corenet.local:8443:127.0.0.1 \
  https://static.corenet.local:8443/anything | grep pool

# header-based steering → static pool, despite the /api path
curl -sk --http2 -H 'x-canary: static' https://localhost:8443/api/users | grep pool

# default              → api pool
curl -sk --http2 https://localhost:8443/api/users | grep pool
```

The third one is the point: an `/api/*` request lands on the **static** pool
purely because of a request header. That is only possible after decryption —
an L4 balancer physically cannot do it.

Gateway log: `🗺️ L7-ROUTE  Route header:x-canary matched → pool static`

### 4.5 — HTTP/2 multiplexing (the headline result)

```bash
curl -sk --http2 --parallel \
  -o /dev/null "https://localhost:8443/api/s1?delay=1200" \
  -o /dev/null "https://localhost:8443/api/s2?delay=1200" \
  -o /dev/null "https://localhost:8443/api/s3?delay=1200" \
  -o /dev/null "https://localhost:8443/api/s4?delay=1200" \
  -o /dev/null "https://localhost:8443/api/s5?delay=1200"
```

> ⚠️ **Do not add `--parallel-immediate`.** It tells curl to open every
> connection at once, *before* it knows the server speaks h2 — so you get five
> separate TCP connections and five TLS handshakes, and you have measured
> nothing. Plain `--parallel` makes curl establish one connection, discover h2
> via ALPN, and multiplex the rest onto it. This flag is the single easiest way
> to accidentally disprove multiplexing on your own machine.

Verified gateway log — **one** TCP accept, **one** handshake, five streams:

```
🔗 L4-TCP   TCP connection accepted from 127.0.0.1:58462
🔐 L5-TLS   [c#19] Handshake COMPLETE — TLSv1.3 cipher=TLS_AES_256_GCM_SHA384
🤝 L5-TLS   [c#19] ALPN negotiated → h2
⚙️  L7-H2    [c#19] Peer SETTINGS received maxConcurrentStreams=100
📬 L7-H2    [c#19 s#1] Stream #1 OPENED — GET /api/s1 (1 stream(s) live on this single TCP connection)
📬 L7-H2    [c#19 s#3] Stream #3 OPENED — GET /api/s2 (2 stream(s) live ...)
📬 L7-H2    [c#19 s#5] Stream #5 OPENED — GET /api/s3 (3 stream(s) live ...)
📬 L7-H2    [c#19 s#7] Stream #7 OPENED — GET /api/s4 (4 stream(s) live ...)
📬 L7-H2    [c#19 s#9] Stream #9 OPENED — GET /api/s5 (5 stream(s) live ...)
📪 L7-H2    [c#19 s#1] Stream #1 CLOSED (4 still live; TCP connection stays UP)
🧹 L7-H2    [c#19] Session closed — carried 5 streams over ONE TCP connection (peak concurrency 5)
```

Three things to notice:

1. **One `c#19`.** Five requests, one connection, one handshake.
2. **Stream IDs 1, 3, 5, 7, 9.** Odd IDs are client-initiated by RFC 9113;
   even IDs are reserved for server push, which we disable.
3. **Five streams live simultaneously.** Each backend held its response for
   1200 ms, yet all five were in flight at once.

### 4.6 — The measurement that proves it: HTTP/2 vs HTTP/1.1

```bash
# HTTP/1.1: three 1.2s requests, serialised on one connection
time curl -sk --http1.1 \
  -o /dev/null "https://localhost:8443/api/a?delay=1200" \
  -o /dev/null "https://localhost:8443/api/b?delay=1200" \
  -o /dev/null "https://localhost:8443/api/c?delay=1200"

# HTTP/2: identical work, multiplexed
time curl -sk --http2 --parallel \
  -o /dev/null "https://localhost:8443/api/a?delay=1200" \
  -o /dev/null "https://localhost:8443/api/b?delay=1200" \
  -o /dev/null "https://localhost:8443/api/c?delay=1200"
```

Measured on the reference machine:

| Protocol | Wall clock | Why |
|---|---|---|
| HTTP/1.1 | **3.63 s** | ≈ 3 × 1.2 s. One request per connection at a time — head-of-line blocking. |
| HTTP/2 | **1.23 s** | ≈ 1 × 1.2 s. All three streams interleaved on one connection. |

Both hit the same port, same certificate, same handler. The only variable is
the ALPN result. That is the entire value proposition of HTTP/2 in one diff.

### 4.7 — HTTP/1.1 and HTTP/2 on the same socket

```bash
curl -vk --http1.1 https://localhost:8443/api/users 2>&1 | grep -E "ALPN|HTTP"
```

```
* ALPN: curl offers http/1.1
* ALPN: server accepted http/1.1
< HTTP/1.1 200 OK
< x-corenet-protocol: HTTP/1.1
```

This works because of `allowHTTP1: true` on `http2.createSecureServer()`.
Without it, an `http/1.1` ALPN result is a hard failure — a genuinely common
production outage when a legacy client meets a new h2-only edge.

### 4.8 — Health checking and failover

```bash
curl -s http://127.0.0.1:9002/__toggle          # take api-bravo down
sleep 6                                          # let the prober notice
for i in $(seq 1 6); do curl -sk --http2 https://localhost:8443/api/users | grep servedBy; done
curl -s http://127.0.0.1:9002/__toggle          # bring it back
sleep 6
for i in $(seq 1 3); do curl -sk --http2 https://localhost:8443/api/users | grep servedBy; done
```

Verified: while `api-bravo` is down the rotation collapses to alpha/charlie
only, and it rejoins on its own once the prober sees a 200.

```
💔 HEALTH  api-bravo(127.0.0.1:9002) transitioned to UNHEALTHY — evicted from the rotation
💚 HEALTH  api-bravo(127.0.0.1:9002) transitioned to HEALTHY — back in the Round-Robin rotation
```

Note the two independent mechanisms: **passive** detection marks a target down
the instant a request gets `ECONNREFUSED` (fast, but only learns from real
traffic), while **active** probing is what lets a recovered target rejoin
without a request having to fail first.

### 4.9 — Client cancellation → RST_STREAM

```bash
curl -sk --http2 --max-time 1 "https://localhost:8443/api/slow?delay=8000"
```

```
✂️ L7-H2  [c#21 s#1] Client cancelled — sending RST/abort upstream (no orphaned backend work)
```

```
✂️ L7-H2     [c#1 s#1] Client cancelled — sending RST/abort upstream (no orphaned backend work)
🧯 UPSTREAM  [c#1 s#1] Upstream socket torn down by us after client cancellation (ECONNRESET — api-alpha NOT penalised)
```

A proxy that ignores this keeps doing work nobody will read. At scale that is
how a load balancer melts down behind a client-side timeout storm.

**The trap hiding in that second line.** Cancelling means calling
`upstreamReq.destroy()` — which comes back to your own error handler as an
`ECONNRESET`. If you treat every `ECONNRESET` as evidence of a sick origin
(a very natural thing to write), you will mark down a backend that did nothing
wrong. A client-side timeout storm then walks the entire fleet out of rotation
and you have converted a client problem into a total outage. `forward()` carries
a `clientAborted` flag specifically to tell "the origin died" apart from "we hung
up on the origin". Verified: three cancellations in a row leave all five targets
at `healthy=true, failures=0`.

### 4.10 — Edge-terminated endpoints

```bash
curl -sk --http2 https://localhost:8443/__gateway/stats | head -30
curl -sk --http2 https://localhost:8443/healthz
```

`/__gateway/stats` never touches a backend — it reports live counters
(`h2Sessions`, `h2Streams`, `peakConcurrentStreams`, per-route hit counts) and
the full pool state including each target's resolved address, health, and
served count. Useful for confirming the Round-Robin cursor is where you expect.

### 4.11 — Backend simulation knobs

| Query / path | Effect |
|---|---|
| `?delay=2000` | Origin holds the response 2 s — the multiplexing and cancellation demos |
| `?fail=1` | Origin returns 500 — watch the proxy pass it through rather than retry (5xx is an *application* answer, not a transport failure) |
| `?size=1048576` | 1 MB body — watch HTTP/2 flow control and `WINDOW_UPDATE` |
| `/__toggle` (direct to origin port) | Flip health state |
| `/__health` (direct to origin port) | What the prober sees |

---

## 5. Things worth breaking on purpose

Each of these is a one-line change that teaches something:

- Set `MAX_CONCURRENT_STREAMS=2` and rerun 4.5. Measured result: curl does **not** queue — it honours the SETTINGS frame by opening a *second* TCP connection and putting two streams on each (`c#3 s#1, s#3` and `c#4 s#1, s#3`). Wall clock stays flat, but you have paid for an extra handshake. This is exactly the trade-off a real edge tunes: too low a stream limit and clients silently fan back out into more connections.
- Delete the `if (key.startsWith(':')) continue;` line in `buildUpstreamHeaders()` and send an h2 request. You get `ERR_INVALID_HTTP_TOKEN`, which is HTTP/2's pseudo-header design colliding with HTTP/1.1's grammar.
- Delete the hop-by-hop filter in `buildDownstreamHeaders()`. The origin's `connection: keep-alive` now reaches an h2 stream: `ERR_HTTP2_INVALID_CONNECTION_HEADERS`.
- Set `ALPNProtocols: ['http/1.1']` and rerun 4.5 with `--http2`. Multiplexing disappears; the timing collapses back to 3.6 s.
- Remove `allowHTTP1: true` and run 4.7. Legacy clients are locked out entirely.
- Point a target at a port with nothing on it and watch the retry path: `🔁 L7-LB ECONNREFUSED — replaying onto the next Round-Robin target`.
