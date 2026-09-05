#!/usr/bin/env node
'use strict';

/**
 * ============================================================================
 *  CoreNet-Proxy :: gateway.js
 *  A native Node.js Layer 7 reverse proxy + load balancer.
 *  ZERO external dependencies. Core modules only.
 * ============================================================================
 *
 *  This single file boots TWO things so the whole topology is observable in
 *  one terminal:
 *
 *    (A) A fleet of mock HTTP/1.1 origin servers on internal loopback ports.
 *        These are "the backends". They speak PLAINTEXT http. They never see
 *        a TLS record in their life.
 *
 *    (B) The edge gateway: an http2.createSecureServer() bound to :8443 that
 *        terminates TCP + TLS 1.3, negotiates ALPN (h2 or http/1.1), decrypts,
 *        parses the L7 request (:method / :path / :authority / headers),
 *        selects a backend pool by route rule, picks a target via Round-Robin,
 *        and streams the request over a pooled keep-alive TCP connection.
 *
 *  The layering, bottom-up, is the whole point of the project:
 *
 *      L4  TCP accept .......... server.on('connection')
 *      L5  TLS 1.3 handshake ... server.on('secureConnection') + SNICallback
 *      L6  ALPN selection ...... socket.alpnProtocol -> 'h2' | 'http/1.1'
 *      L7  HTTP/2 framing ...... server.on('session') / server.on('stream')
 *      L7  Routing ............. path + :authority inspection
 *      L7  Balancing ........... Round-Robin over healthy targets
 *      L4  Upstream ............ plaintext http.request over a keep-alive Agent
 */

const http   = require('node:http');
const http2  = require('node:http2');
const fs     = require('node:fs');
const path   = require('node:path');
const dns    = require('node:dns');
const crypto = require('node:crypto');

// ===========================================================================
// SECTION 0 :: CONFIGURATION
// ===========================================================================

const CONFIG = {
  gatewayPort:        Number(process.env.GATEWAY_PORT || 8443),
  gatewayHost:        process.env.GATEWAY_HOST || '0.0.0.0',

  tlsKeyPath:         process.env.TLS_KEY  || path.join(__dirname, 'key.pem'),
  tlsCertPath:        process.env.TLS_CERT || path.join(__dirname, 'cert.pem'),

  // Force the cryptographic floor to TLS 1.3. Set MIN_TLS=TLSv1.2 to watch a
  // client negotiate down and compare the handshake round-trips in `curl -v`.
  minTlsVersion:      process.env.MIN_TLS || 'TLSv1.3',

  // How many concurrent HTTP/2 streams a single client TCP connection may
  // hold open. This is the literal multiplexing budget advertised in the
  // SETTINGS frame during connection preface.
  maxConcurrentStreams: Number(process.env.MAX_CONCURRENT_STREAMS || 100),

  upstreamTimeoutMs:  Number(process.env.UPSTREAM_TIMEOUT_MS || 15_000),
  healthIntervalMs:   Number(process.env.HEALTH_INTERVAL_MS || 5_000),
  healthTimeoutMs:    Number(process.env.HEALTH_TIMEOUT_MS  || 1_000),

  startBackends:      !process.argv.includes('--no-backends'),
  startGateway:       !process.argv.includes('--no-gateway'),
  verbose:            !process.argv.includes('--quiet'),
};

// ---------------------------------------------------------------------------
// TOPOLOGY
// ---------------------------------------------------------------------------
// Note the deliberate asymmetry: the `api` pool is addressed by the HOSTNAME
// "localhost", the `static` pool by the raw IP "127.0.0.1". At boot the
// gateway runs a real dns.lookup() on the named targets and caches the
// resolved address -- exactly how a production proxy keeps a resolver cache
// instead of paying a DNS round trip per request.
// ---------------------------------------------------------------------------

const BACKENDS = [
  { name: 'api-alpha',    pool: 'api',    host: 'localhost', port: 9001 },
  { name: 'api-bravo',    pool: 'api',    host: 'localhost', port: 9002 },
  { name: 'api-charlie',  pool: 'api',    host: 'localhost', port: 9003 },
  { name: 'static-delta', pool: 'static', host: '127.0.0.1', port: 9101 },
  { name: 'static-echo',  pool: 'static', host: '127.0.0.1', port: 9102 },
];

// L7 routing table, evaluated top-down, first match wins.
// Each rule gets the decrypted request surface: method, pathname, authority
// (the HTTP/2 pseudo-header that replaced the Host header) and headers.
const ROUTES = [
  {
    id: 'host:static',
    describe: 'Virtual-host match on :authority == static.corenet.local',
    match: (r) => r.hostname === 'static.corenet.local',
    pool: 'static',
  },
  {
    id: 'path:/static',
    describe: 'Path-prefix match on /static/*',
    match: (r) => r.pathname === '/static' || r.pathname.startsWith('/static/'),
    pool: 'static',
  },
  {
    id: 'header:x-canary',
    describe: 'Header match on x-canary: static (demonstrates header-based L7 steering)',
    match: (r) => r.headers['x-canary'] === 'static',
    pool: 'static',
  },
  {
    id: 'path:/api',
    describe: 'Path-prefix match on /api/*',
    match: (r) => r.pathname === '/api' || r.pathname.startsWith('/api/'),
    pool: 'api',
  },
  {
    id: 'default',
    describe: 'Catch-all fallback',
    match: () => true,
    pool: 'api',
  },
];

// ===========================================================================
// SECTION 1 :: LOGGING  (the "explanatory architecture log")
// ===========================================================================

const ANSI = process.stdout.isTTY && !process.env.NO_COLOR
  ? {
      reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
      red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
      blue: '\x1b[34m', magenta: '\x1b[35m', cyan: '\x1b[36m', grey: '\x1b[90m',
    }
  : new Proxy({}, { get: () => '' });

function clock() {
  const d = new Date();
  return d.toISOString().slice(11, 23); // HH:MM:SS.mmm
}

/**
 * log(emoji, layer, message, context)
 *   layer   - which OSI-ish band the event belongs to; colourised so you can
 *             visually scan a connection's vertical journey up the stack.
 *   context - short correlation tag e.g. "c#3 s#5" (connection 3, stream 5).
 */
function log(emoji, layer, message, context = '') {
  if (!CONFIG.verbose) return;
  const colors = {
    'L4-TCP':   ANSI.blue,
    'L5-TLS':   ANSI.magenta,
    'L7-H2':    ANSI.cyan,
    'L7-H1':    ANSI.cyan,
    'L7-ROUTE': ANSI.yellow,
    'L7-LB':    ANSI.yellow,
    'UPSTREAM': ANSI.green,
    'BACKEND':  ANSI.green,
    'HEALTH':   ANSI.grey,
    'BOOT':     ANSI.bold,
    'ERROR':    ANSI.red,
    'DNS':      ANSI.magenta,
  };
  const c = colors[layer] || '';
  const tag = context ? `${ANSI.grey}[${context}]${ANSI.reset} ` : '';
  process.stdout.write(
    `${ANSI.grey}${clock()}${ANSI.reset} ${emoji}  ${c}${layer.padEnd(8)}${ANSI.reset} ${tag}${message}\n`
  );
}

function bytes(n) {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1048576).toFixed(2)}MB`;
}

// ===========================================================================
// SECTION 2 :: THE MOCK BACKENDS  (plaintext HTTP/1.1 origins)
// ===========================================================================
//
// These are intentionally dumb HTTP/1.1 servers. They prove a key point:
// the origin fleet needs no TLS, no certificate, no HTTP/2 support. All of
// that complexity is absorbed once, at the edge.
//
// Each backend exposes control endpoints for the demos:
//   /__health          -> liveness probe consumed by the gateway's checker
//   /__toggle          -> flip this backend healthy <-> unhealthy (failover demo)
//   ?delay=<ms>        -> hold the response open (multiplexing / interleave demo)
//   ?fail=1            -> return 500 (error-propagation demo)
//   ?size=<bytes>      -> return a payload of N bytes (flow-control demo)
// ---------------------------------------------------------------------------

const backendRuntime = new Map(); // name -> { requests, healthy, server }

function startBackend(def) {
  const state = { requests: 0, healthy: true, server: null };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'backend.local'}`);

    // ---- control plane -----------------------------------------------------
    if (url.pathname === '/__health') {
      const code = state.healthy ? 200 : 503;
      res.writeHead(code, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ backend: def.name, healthy: state.healthy }));
    }
    if (url.pathname === '/__toggle') {
      state.healthy = !state.healthy;
      log(state.healthy ? '💚' : '💔', 'BACKEND',
        `${ANSI.bold}${def.name}${ANSI.reset} manually flipped to ${state.healthy ? 'HEALTHY' : 'UNHEALTHY'}`);
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ backend: def.name, healthy: state.healthy }));
    }

    // ---- data plane --------------------------------------------------------
    state.requests += 1;
    const n = state.requests;
    const reqId = req.headers['x-request-id'] || '-';
    const delay = Math.min(Number(url.searchParams.get('delay')) || 0, 30_000);
    const fail  = url.searchParams.get('fail') === '1';
    const size  = Math.min(Number(url.searchParams.get('size')) || 0, 8 * 1024 * 1024);

    log('📥', 'BACKEND',
      `${ANSI.bold}${def.name}${ANSI.reset}:${def.port} received ` +
      `${req.method} ${url.pathname}${url.search} over HTTP/${req.httpVersion} (plaintext)` +
      (delay ? ` ${ANSI.grey}holding ${delay}ms${ANSI.reset}` : ''),
      `req ${reqId}`);

    // Drain any request body so keep-alive sockets stay reusable.
    let bodyLen = 0;
    req.on('data', (chunk) => { bodyLen += chunk.length; });

    req.on('end', () => {
      const respond = () => {
        if (res.destroyed) return; // client (or the proxy) gave up on us

        if (fail) {
          res.writeHead(500, { 'content-type': 'application/json', 'x-served-by': def.name });
          return res.end(JSON.stringify({ error: 'simulated backend failure', backend: def.name }));
        }

        const payload = {
          message:        'Hello from a plaintext origin server.',
          servedBy:       def.name,
          pool:           def.pool,
          originPort:     def.port,
          pid:            process.pid,
          requestNumber:  n,
          method:         req.method,
          path:           url.pathname + url.search,
          originProtocol: `HTTP/${req.httpVersion} (no TLS on this hop)`,
          requestBodyBytes: bodyLen,
          // Echo back what the edge told us about the original client. This is
          // the only way an origin can learn anything about the TLS session,
          // because the origin never saw it.
          forwarded: {
            'x-request-id':        req.headers['x-request-id'] || null,
            'x-forwarded-for':     req.headers['x-forwarded-for'] || null,
            'x-forwarded-proto':   req.headers['x-forwarded-proto'] || null,
            'x-forwarded-host':    req.headers['x-forwarded-host'] || null,
            'x-forwarded-tls':     req.headers['x-forwarded-tls'] || null,
            'x-forwarded-alpn':    req.headers['x-forwarded-alpn'] || null,
          },
        };

        let body = JSON.stringify(payload, null, 2);
        if (size > 0) body = body + '\n' + 'x'.repeat(size); // filler for flow-control demos

        res.writeHead(200, {
          'content-type':   'application/json; charset=utf-8',
          'content-length': Buffer.byteLength(body),
          'x-served-by':    def.name,
          'x-origin-port':  String(def.port),
          // Deliberately hop-by-hop: proves the gateway strips these before
          // writing to an HTTP/2 stream (h2 forbids connection-specific headers).
          'connection':     'keep-alive',
          'keep-alive':     'timeout=5',
        });
        res.end(body);

        log('📤', 'BACKEND',
          `${ANSI.bold}${def.name}${ANSI.reset} responded 200 ${bytes(Buffer.byteLength(body))}`,
          `req ${reqId}`);
      };

      if (delay > 0) setTimeout(respond, delay);
      else respond();
    });
  });

  server.keepAliveTimeout = 30_000;
  server.headersTimeout   = 35_000;

  state.server = server;
  backendRuntime.set(def.name, state);

  return new Promise((resolve, reject) => {
    // A listen failure must REJECT, not just log. Resolving only on 'listening'
    // means EADDRINUSE leaves this promise pending forever, so the awaiting
    // Promise.all() in main() never settles and the gateway silently never
    // starts -- a hang with no error, which is far worse than a crash.
    const onError = (err) => {
      server.removeListener('listening', onListening);
      reject(Object.assign(err, { backendName: def.name, backendPort: def.port }));
    };
    const onListening = () => {
      server.removeListener('error', onError);
      // From here on, runtime errors are logged rather than fatal.
      server.on('error', (err) => log('🔥', 'ERROR', `backend ${def.name} error: ${err.message}`));
      log('🟢', 'BOOT', `Origin ${ANSI.bold}${def.name}${ANSI.reset} listening on http://127.0.0.1:${def.port} ${ANSI.grey}(pool=${def.pool}, plaintext HTTP/1.1)${ANSI.reset}`);
      resolve(server);
    };
    server.once('error', onError);
    server.once('listening', onListening);
    // Bind to loopback only. These ports must never be reachable from outside
    // the host -- the gateway is the sole ingress.
    server.listen(def.port, '127.0.0.1');
  });
}

// ===========================================================================
// SECTION 3 :: DNS RESOLUTION OF UPSTREAM TARGETS
// ===========================================================================
//
// A reverse proxy that connects to backends by name must resolve those names.
// Doing it per-request adds a DNS round trip to every hop; doing it once at
// boot (or on a TTL timer) is what real proxies do. We resolve once and log
// the mapping so the name -> address step is visible rather than magic.
// ---------------------------------------------------------------------------

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

async function resolveTargets(targets) {
  for (const t of targets) {
    if (IPV4_RE.test(t.host) || t.host === '::1') {
      t.address = t.host;
      log('🧭', 'DNS', `${ANSI.bold}${t.name}${ANSI.reset} target "${t.host}" is a literal IP ${ANSI.grey}(no resolver needed)${ANSI.reset}`);
      continue;
    }
    try {
      // family: 4 keeps us off ::1, since the origins bind to 127.0.0.1.
      const { address, family } = await dns.promises.lookup(t.host, { family: 4 });
      t.address = address;
      log('🧭', 'DNS', `${ANSI.bold}${t.name}${ANSI.reset} resolved "${t.host}" → ${ANSI.bold}${address}${ANSI.reset} (IPv${family}) ${ANSI.grey}cached for the process lifetime${ANSI.reset}`);
    } catch (err) {
      t.address = t.host;
      log('🔥', 'ERROR', `DNS lookup failed for ${t.host}: ${err.message} — falling back to the literal name`);
    }
  }
}

// ===========================================================================
// SECTION 4 :: LOAD BALANCER  (Round-Robin + active health checking)
// ===========================================================================

class Target {
  constructor(def) {
    this.name    = def.name;
    this.host    = def.host;       // configured name
    this.address = def.host;       // resolved IP, filled in by resolveTargets()
    this.port    = def.port;
    this.pool    = def.pool;
    this.healthy = true;
    this.inFlight = 0;
    this.served   = 0;
    this.failures = 0;
    this.lastError = null;
  }
  get label() { return `${this.name}(${this.address}:${this.port})`; }
}

class RoundRobinPool {
  constructor(name, targets) {
    this.name    = name;
    this.targets = targets;
    // The entire Round-Robin algorithm is this one integer. Everything else
    // in a load balancer is health, retry and observability around it.
    this.cursor  = 0;
    this.agent   = new http.Agent({
      keepAlive: true,          // reuse upstream TCP sockets across requests
      keepAliveMsecs: 10_000,
      maxSockets: 128,          // per origin host:port
      maxFreeSockets: 16,
      timeout: CONFIG.upstreamTimeoutMs,
    });
  }

  /**
   * Classic Round-Robin with health skipping.
   * Walk at most N slots forward from the cursor; return the first healthy
   * target. If we complete a full lap with nothing healthy, the pool is down.
   * `exclude` lets a retry avoid the target that just failed us.
   */
  next(exclude = new Set()) {
    const n = this.targets.length;
    for (let i = 0; i < n; i++) {
      const idx = this.cursor % n;
      this.cursor = (this.cursor + 1) % n;
      const t = this.targets[idx];
      if (t.healthy && !exclude.has(t.name)) return t;
    }
    return null;
  }

  snapshot() {
    return {
      pool: this.name,
      cursor: this.cursor,
      targets: this.targets.map((t) => ({
        name: t.name, host: t.host, address: t.address, port: t.port,
        healthy: t.healthy, served: t.served, inFlight: t.inFlight,
        failures: t.failures, lastError: t.lastError,
      })),
    };
  }
}

const pools = new Map();

function buildPools() {
  for (const def of BACKENDS) {
    if (!pools.has(def.pool)) pools.set(def.pool, new RoundRobinPool(def.pool, []));
    pools.get(def.pool).targets.push(new Target(def));
  }
}

function allTargets() {
  return [...pools.values()].flatMap((p) => p.targets);
}

/**
 * Active health checking.
 * Passive failure detection (mark-down on connect error) is reactive and
 * leaves a target black-holed until traffic happens to hit it. An active
 * prober is what lets a recovered backend rejoin the rotation on its own.
 */
function startHealthChecks() {
  const probe = (t) => new Promise((resolve) => {
    const req = http.request(
      { host: t.address, port: t.port, path: '/__health', method: 'GET', timeout: CONFIG.healthTimeoutMs },
      (res) => {
        res.resume(); // drain
        resolve(res.statusCode === 200);
      }
    );
    req.on('timeout', () => { req.destroy(new Error('health probe timeout')); });
    req.on('error', () => resolve(false));
    req.end();
  });

  const tick = async () => {
    for (const t of allTargets()) {
      const ok = await probe(t);
      if (ok !== t.healthy) {
        t.healthy = ok;
        log(ok ? '💚' : '💔', 'HEALTH',
          `${ANSI.bold}${t.label}${ANSI.reset} transitioned to ${ok ? `${ANSI.green}HEALTHY — back in the Round-Robin rotation` : `${ANSI.red}UNHEALTHY — evicted from the rotation`}${ANSI.reset}`);
      }
    }
  };

  const timer = setInterval(tick, CONFIG.healthIntervalMs);
  timer.unref(); // never hold the event loop open just for probing
  tick();
  return timer;
}

// ===========================================================================
// SECTION 5 :: L7 ROUTING + HEADER HYGIENE
// ===========================================================================

// RFC 9110 hop-by-hop headers. These describe a single transport hop and must
// NEVER be forwarded. On top of correctness, HTTP/2 outright FORBIDS them:
// writing `connection: keep-alive` onto an h2 stream throws
// ERR_HTTP2_INVALID_CONNECTION_HEADERS.
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

function pickRoute(surface) {
  for (const rule of ROUTES) {
    if (rule.match(surface)) return rule;
  }
  return ROUTES[ROUTES.length - 1];
}

/**
 * Translate an inbound request (HTTP/2 OR HTTP/1.1) into headers safe for a
 * plaintext HTTP/1.1 upstream request.
 *
 * The HTTP/2 half matters most: h2 has no Host header and no request line.
 * It carries :method, :scheme, :authority and :path as pseudo-headers, and
 * Node's compat layer leaves them sitting in req.headers. They are illegal
 * as HTTP/1.1 field names (the ':' is not a valid token character), so
 * http.request() would throw ERR_INVALID_HTTP_TOKEN if we passed them through.
 */
function buildUpstreamHeaders(req, ctx, target) {
  const out = {};

  for (const [key, value] of Object.entries(req.headers)) {
    if (key.startsWith(':')) continue;              // strip h2 pseudo-headers
    if (HOP_BY_HOP.has(key.toLowerCase())) continue; // strip hop-by-hop
    if (key.toLowerCase() === 'host') continue;      // we rewrite this below
    out[key] = value;
  }

  // The origin's view of "who am I". Point it at the real upstream.
  out['host'] = `${target.host}:${target.port}`;

  // The X-Forwarded-* family: the origin's ONLY window into the TLS session
  // it never participated in.
  const priorXff = req.headers['x-forwarded-for'];
  out['x-forwarded-for']   = priorXff ? `${priorXff}, ${ctx.clientIp}` : ctx.clientIp;
  out['x-forwarded-proto'] = 'https';
  out['x-forwarded-host']  = ctx.hostname || '';
  out['x-forwarded-port']  = String(CONFIG.gatewayPort);
  out['x-forwarded-tls']   = ctx.tlsProtocol || 'unknown';
  out['x-forwarded-alpn']  = ctx.alpn || 'unknown';
  out['x-request-id']      = ctx.reqId;
  out['via']               = `${ctx.httpVersion} corenet-proxy`;

  return out;
}

/** Filter an upstream HTTP/1.1 response's headers for safe downstream write. */
function buildDownstreamHeaders(upstreamRes, ctx, target) {
  const out = {};
  for (const [key, value] of Object.entries(upstreamRes.headers)) {
    if (HOP_BY_HOP.has(key.toLowerCase())) continue;
    out[key] = value;
  }
  out['x-corenet-backend']  = target.name;
  out['x-corenet-pool']     = target.pool;
  out['x-corenet-route']    = ctx.routeId;
  out['x-corenet-protocol'] = ctx.httpVersion;
  out['x-request-id']       = ctx.reqId;
  return out;
}

// ===========================================================================
// SECTION 6 :: THE PROXY DATA PATH
// ===========================================================================

const stats = {
  startedAt: new Date().toISOString(),
  tcpConnections: 0,
  tlsHandshakes: 0,
  h2Sessions: 0,
  h2Streams: 0,
  h1Requests: 0,
  proxied: 0,
  errors: 0,
  peakConcurrentStreams: 0,
  byRoute: Object.create(null),
};

function safeJson(res, status, obj, ctx) {
  try {
    if (res.writableEnded || res.destroyed) return;
    const body = JSON.stringify(obj, null, 2);
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': Buffer.byteLength(body),
      ...(ctx ? { 'x-request-id': ctx.reqId } : {}),
    });
    res.end(body);
  } catch {
    /* stream already torn down by the peer; nothing to do */
  }
}

/**
 * The core request handler. Node's http2 compatibility layer hands us
 * http.IncomingMessage-shaped objects for BOTH h2 streams and h1 requests,
 * so one handler serves both protocols -- which is exactly the abstraction a
 * real gateway wants.
 */
function handleRequest(req, res) {
  const t0 = process.hrtime.bigint();

  // --- Identify the transport this request arrived on ---------------------
  const isH2      = Boolean(req.stream);                 // set only by the h2 compat layer
  const streamId  = isH2 ? req.stream.id : null;
  const socket    = isH2 ? req.stream.session.socket : req.socket;
  const connId    = (socket && socket.__connId) || 0;
  const tag       = isH2 ? `c#${connId} s#${streamId}` : `c#${connId} h1`;

  const ctx = {
    reqId:       crypto.randomUUID().slice(0, 8),
    clientIp:    (socket && socket.remoteAddress) || '127.0.0.1',
    httpVersion: isH2 ? 'HTTP/2.0' : `HTTP/${req.httpVersion}`,
    alpn:        (socket && socket.alpnProtocol) || (isH2 ? 'h2' : 'http/1.1'),
    tlsProtocol: (socket && typeof socket.getProtocol === 'function' && socket.getProtocol()) || 'unknown',
    hostname:    null,
    routeId:     null,
  };

  // --- L7 INSPECTION -------------------------------------------------------
  // For h2 the authority comes from the :authority pseudo-header; for h1 from
  // the Host header. Node normalises the former onto req.authority.
  const authority = (isH2 ? req.authority : null) || req.headers[':authority'] || req.headers.host || 'localhost';
  ctx.hostname = String(authority).split(':')[0];

  let parsed;
  try {
    parsed = new URL(req.url, `https://${authority}`);
  } catch {
    stats.errors++;
    return safeJson(res, 400, { error: 'malformed request target', target: req.url }, ctx);
  }

  log('🔎', 'L7-ROUTE',
    `Inspecting decrypted request → ${ANSI.bold}${req.method} ${parsed.pathname}${parsed.search}${ANSI.reset} ` +
    `${ANSI.grey}authority=${authority} proto=${ctx.httpVersion} ua=${(req.headers['user-agent'] || '-').slice(0, 28)}${ANSI.reset}`,
    tag);

  // --- Edge-terminated endpoints (never proxied) ---------------------------
  if (parsed.pathname === '/healthz') {
    return safeJson(res, 200, { status: 'ok', role: 'edge-gateway', uptimeSec: Math.round(process.uptime()) }, ctx);
  }
  if (parsed.pathname === '/__gateway/stats') {
    log('📊', 'L7-ROUTE', 'Request terminated AT THE EDGE — no backend involved', tag);
    return safeJson(res, 200, {
      gateway: {
        ...stats,
        tls: { minVersion: CONFIG.minTlsVersion, alpn: ['h2', 'http/1.1'] },
        maxConcurrentStreams: CONFIG.maxConcurrentStreams,
      },
      pools: [...pools.values()].map((p) => p.snapshot()),
      routes: ROUTES.map((r) => ({ id: r.id, pool: r.pool, describe: r.describe })),
    }, ctx);
  }

  // --- ROUTE SELECTION -----------------------------------------------------
  const route = pickRoute({
    method:   req.method,
    pathname: parsed.pathname,
    hostname: ctx.hostname,
    headers:  req.headers,
  });
  ctx.routeId = route.id;
  stats.byRoute[route.id] = (stats.byRoute[route.id] || 0) + 1;

  const pool = pools.get(route.pool);
  log('🗺️ ', 'L7-ROUTE',
    `Route ${ANSI.bold}${route.id}${ANSI.reset} matched → pool ${ANSI.bold}${route.pool}${ANSI.reset} ${ANSI.grey}(${route.describe})${ANSI.reset}`,
    tag);

  if (!pool) {
    stats.errors++;
    return safeJson(res, 503, { error: 'no pool configured for route', route: route.id }, ctx);
  }

  forward(req, res, ctx, pool, tag, t0, new Set(), 0);
}

/**
 * Send the request upstream. Retries onto the next Round-Robin target when a
 * connection-level failure happens BEFORE any response byte reached the
 * client, and only for methods that are safe to replay.
 */
function forward(req, res, ctx, pool, tag, t0, excluded, attempt) {
  const target = pool.next(excluded);

  if (!target) {
    stats.errors++;
    log('🛑', 'ERROR', `Pool ${ANSI.bold}${pool.name}${ANSI.reset} has no healthy targets — returning 503`, tag);
    return safeJson(res, 503, { error: 'no healthy upstream', pool: pool.name, requestId: ctx.reqId }, ctx);
  }

  log('⚖️ ', 'L7-LB',
    `Round-Robin selected ${ANSI.bold}${target.label}${ANSI.reset} ` +
    `${ANSI.grey}(cursor now ${pool.cursor}/${pool.targets.length}` +
    `${attempt > 0 ? `, retry #${attempt}` : ''})${ANSI.reset}`,
    tag);

  const headers = buildUpstreamHeaders(req, ctx, target);

  const upstreamReq = http.request({
    host:    target.address,      // pre-resolved: no per-request DNS lookup
    port:    target.port,
    method:  req.method,
    path:    req.url,             // raw target, query string intact
    headers,
    agent:   pool.agent,          // keep-alive pooling to the origin
  });

  target.inFlight += 1;
  let responded     = false;
  let bodyStarted   = false;
  let settled       = false;
  // Set when WE tear down the upstream because the client walked away. Without
  // this flag, our own destroy() surfaces as an ECONNRESET on upstreamReq and
  // the error handler below would blame a perfectly healthy origin -- so a
  // client-side timeout storm would mark the whole fleet unhealthy.
  let clientAborted = false;

  const release = () => {
    if (settled) return;
    settled = true;
    target.inFlight -= 1;
  };

  // Do not replay a request whose body we have already streamed upstream, and
  // do not replay non-idempotent methods. This is the correctness boundary of
  // proxy retries.
  const replayable = ['GET', 'HEAD', 'OPTIONS'].includes(req.method);

  upstreamReq.on('socket', (sock) => {
    // reusedSocket tells you whether the Agent handed us a warm TCP connection.
    // Warm socket == no TCP handshake on this hop. That is the backend-side
    // analogue of what HTTP/2 multiplexing does on the client side.
    queueMicrotask(() => {
      log('🔌', 'UPSTREAM',
        `Opening plaintext hop → ${target.address}:${target.port} ` +
        `${ANSI.grey}(socket ${upstreamReq.reusedSocket ? 'REUSED from keep-alive pool' : 'newly established'}` +
        `, local ${sock.localAddress || '?'}:${sock.localPort || '?'})${ANSI.reset}`,
        tag);
    });
  });

  upstreamReq.setTimeout(CONFIG.upstreamTimeoutMs, () => {
    log('⏰', 'ERROR', `Upstream ${target.label} timed out after ${CONFIG.upstreamTimeoutMs}ms`, tag);
    upstreamReq.destroy(new Error('upstream timeout'));
  });

  upstreamReq.on('response', (upstreamRes) => {
    responded = true;
    release();
    target.served += 1;
    stats.proxied += 1;

    log('📨', 'UPSTREAM',
      `${target.name} answered ${ANSI.bold}${upstreamRes.statusCode}${ANSI.reset} ` +
      `${ANSI.grey}HTTP/${upstreamRes.httpVersion} — translating headers for ${ctx.httpVersion}${ANSI.reset}`,
      tag);

    const downstream = buildDownstreamHeaders(upstreamRes, ctx, target);

    try {
      res.writeHead(upstreamRes.statusCode, downstream);
    } catch (err) {
      log('🔥', 'ERROR', `Failed to write response head: ${err.message}`, tag);
      upstreamRes.destroy();
      return;
    }

    let sent = 0;
    upstreamRes.on('data', (c) => { sent += c.length; });

    // The actual proxying: two streams, one pipe. Backpressure propagates
    // end-to-end, and for h2 it becomes per-stream WINDOW_UPDATE frames.
    upstreamRes.pipe(res);

    log('🚿', 'UPSTREAM', `Piping origin body → ${ctx.httpVersion} ${ANSI.grey}(backpressure-aware)${ANSI.reset}`, tag);

    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      log('✅', isStreamTag(tag) ? 'L7-H2' : 'L7-H1',
        `Response complete ${ANSI.bold}${upstreamRes.statusCode}${ANSI.reset} ${bytes(sent)} ` +
        `via ${ANSI.bold}${target.name}${ANSI.reset} in ${ANSI.bold}${ms.toFixed(1)}ms${ANSI.reset}`,
        tag);
    });
  });

  upstreamReq.on('error', (err) => {
    release();

    // Self-inflicted teardown after a client cancellation is not upstream
    // evidence. Do not count it as a failure, do not mark the target down,
    // and do not try to write a 502 onto a stream that is already gone.
    if (clientAborted) {
      log('🧯', 'UPSTREAM',
        `Upstream socket torn down by us after client cancellation ` +
        `${ANSI.grey}(${err.code || err.message} — ${target.name} NOT penalised)${ANSI.reset}`,
        tag);
      return;
    }

    target.failures += 1;
    target.lastError = err.message;

    // A connect-level failure is evidence of an unhealthy origin. Mark it down
    // immediately (passive detection); the active prober will let it back in.
    if (['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'ECONNRESET'].includes(err.code)) {
      if (target.healthy) {
        target.healthy = false;
        log('💔', 'HEALTH', `${target.label} marked UNHEALTHY after ${err.code} ${ANSI.grey}(passive detection)${ANSI.reset}`, tag);
      }
    }

    if (!responded && !bodyStarted && replayable && attempt < pool.targets.length - 1) {
      excluded.add(target.name);
      log('🔁', 'L7-LB',
        `${err.code || err.message} on ${target.name} — replaying onto the next Round-Robin target ` +
        `${ANSI.grey}(safe: ${req.method} with no streamed body)${ANSI.reset}`,
        tag);
      return forward(req, res, ctx, pool, tag, t0, excluded, attempt + 1);
    }

    stats.errors++;
    log('🔥', 'ERROR', `Upstream failure, no retry left: ${err.message}`, tag);
    safeJson(res, 502, {
      error: 'bad gateway', detail: err.message, upstream: target.label, requestId: ctx.reqId,
    }, ctx);
  });

  // Client gave up (h2 RST_STREAM, or h1 socket close). Cancel the upstream
  // work instead of letting it run to completion into a dead socket.
  res.on('close', () => {
    if (!res.writableEnded && !upstreamReq.destroyed) {
      clientAborted = true;
      log('✂️ ', isStreamTag(tag) ? 'L7-H2' : 'L7-H1',
        `Client cancelled — sending RST/abort upstream ${ANSI.grey}(no orphaned backend work)${ANSI.reset}`, tag);
      upstreamReq.destroy();
      release();
    }
  });

  // Stream the request body downstream→upstream.
  req.on('data', () => { bodyStarted = true; });
  req.pipe(upstreamReq);
}

function isStreamTag(tag) { return tag.includes(' s#'); }

// ===========================================================================
// SECTION 7 :: THE EDGE — TCP ACCEPT, TLS 1.3 TERMINATION, HTTP/2 SESSIONS
// ===========================================================================

let connSeq = 0;

function createGateway() {
  let key, cert;
  try {
    key  = fs.readFileSync(CONFIG.tlsKeyPath);
    cert = fs.readFileSync(CONFIG.tlsCertPath);
  } catch (err) {
    console.error(`\n${ANSI.red}✖ Could not read TLS material.${ANSI.reset}`);
    console.error(`  key : ${CONFIG.tlsKeyPath}`);
    console.error(`  cert: ${CONFIG.tlsCertPath}`);
    console.error(`  ${err.message}\n`);
    console.error('  Generate them with the OpenSSL command in README.md, then retry.\n');
    process.exit(1);
  }

  const server = http2.createSecureServer({
    key,
    cert,

    // ---- ALPN: the protocol vote that happens INSIDE the TLS handshake ----
    // The client sends its list in ClientHello; we pick the first of ours that
    // it offered. Order matters: h2 wins whenever the client supports it.
    // With TLS 1.3 this costs zero extra round trips — the protocol is chosen
    // before a single byte of HTTP exists.
    ALPNProtocols: ['h2', 'http/1.1'],

    // Serve HTTP/1.1 clients on the same socket/port. Without this, an
    // `http/1.1` ALPN result would be a hard failure.
    allowHTTP1: true,

    minVersion: CONFIG.minTlsVersion,
    honorCipherOrder: true,

    // SETTINGS frame sent in the HTTP/2 connection preface. maxConcurrentStreams
    // is literally the multiplexing budget we grant each TCP connection.
    settings: {
      maxConcurrentStreams: CONFIG.maxConcurrentStreams,
      initialWindowSize: 1024 * 1024,
      enablePush: false,
    },

    // Server Name Indication. The client puts the DNS name it looked up into
    // the ClientHello *in cleartext*, so the server can pick a certificate
    // before any encryption exists. This is the hinge between DNS and TLS.
    SNICallback: (servername, cb) => {
      try {
        log('🏷️ ', 'L5-TLS',
          `SNI in ClientHello: ${ANSI.bold}${servername}${ANSI.reset} ` +
          `${ANSI.grey}(cleartext — this is how one IP serves many certs)${ANSI.reset}`);
      } catch { /* logging must never break a handshake */ }
      cb(null, null); // null context => use the server's default certificate
    },
  });

  // ---- L4: raw TCP accept, before any crypto ------------------------------
  server.on('connection', (socket) => {
    stats.tcpConnections += 1;
    socket.setNoDelay(true); // disable Nagle: latency over throughput at an edge
    log('🔗', 'L4-TCP',
      `TCP connection accepted from ${ANSI.bold}${socket.remoteAddress}:${socket.remotePort}${ANSI.reset} ` +
      `${ANSI.grey}— 3-way handshake done, zero bytes decrypted yet${ANSI.reset}`);
  });

  // ---- L5: TLS handshake finished -----------------------------------------
  // prependListener matters: http2's own secureConnection handler creates the
  // session (and fires 'session') synchronously, so to stamp an id the session
  // logger can read, we must run first.
  server.prependListener('secureConnection', (socket) => {
    socket.__connId = ++connSeq;
    stats.tlsHandshakes += 1;

    const cipher = socket.getCipher() || {};
    const proto  = socket.getProtocol();
    const alpn   = socket.alpnProtocol || '(none)';

    log('🔐', 'L5-TLS',
      `Handshake COMPLETE — ${ANSI.bold}${proto}${ANSI.reset} ` +
      `cipher=${ANSI.bold}${cipher.name || '?'}${ANSI.reset} ` +
      `${ANSI.grey}resumed=${socket.isSessionReused()} sni=${socket.servername || '(none)'}${ANSI.reset}`,
      `c#${socket.__connId}`);

    log('🤝', 'L5-TLS',
      `ALPN negotiated → ${ANSI.bold}${alpn}${ANSI.reset} ` +
      `${ANSI.grey}(${alpn === 'h2' ? 'binary framing, multiplexed streams' : 'text framing, one request per connection at a time'})${ANSI.reset}`,
      `c#${socket.__connId}`);

    log('🔓', 'L5-TLS',
      `TERMINATION POINT — ciphertext ends here; everything upstream is plaintext`,
      `c#${socket.__connId}`);

    socket.on('close', () => {
      log('🔚', 'L4-TCP', `Connection closed`, `c#${socket.__connId}`);
    });
  });

  // ---- L7: one HTTP/2 session per TCP connection --------------------------
  server.on('session', (session) => {
    stats.h2Sessions += 1;
    const connId = (session.socket && session.socket.__connId) || 0;
    const st = { open: 0, total: 0, peak: 0 };
    session.__state = st;

    log('🧵', 'L7-H2',
      `HTTP/2 session established ${ANSI.grey}(connection preface + SETTINGS exchanged; ` +
      `we advertise MAX_CONCURRENT_STREAMS=${CONFIG.maxConcurrentStreams})${ANSI.reset}`,
      `c#${connId}`);

    session.on('remoteSettings', (s) => {
      log('⚙️ ', 'L7-H2',
        `Peer SETTINGS received ${ANSI.grey}maxConcurrentStreams=${s.maxConcurrentStreams} ` +
        `initialWindowSize=${s.initialWindowSize} enablePush=${s.enablePush}${ANSI.reset}`,
        `c#${connId}`);
    });

    session.on('goaway', (code, lastStreamID) => {
      log('👋', 'L7-H2', `GOAWAY errorCode=${code} lastStreamID=${lastStreamID}`, `c#${connId}`);
    });

    session.on('error', (err) => {
      log('🔥', 'ERROR', `Session error: ${err.message}`, `c#${connId}`);
    });

    session.on('close', () => {
      log('🧹', 'L7-H2',
        `Session closed — carried ${ANSI.bold}${st.total}${ANSI.reset} streams over ` +
        `${ANSI.bold}ONE${ANSI.reset} TCP connection ${ANSI.grey}(peak concurrency ${st.peak})${ANSI.reset}`,
        `c#${connId}`);
    });
  });

  // ---- L7: stream lifecycle (the multiplexing evidence) -------------------
  // Registered BEFORE the 'request' handler so it logs first. Node's compat
  // layer adds its own 'stream' listener when the first 'request' listener is
  // attached; both coexist. We only observe here — never consume the stream.
  server.on('stream', (stream, headers) => {
    const connId = (stream.session.socket && stream.session.socket.__connId) || 0;
    const st = stream.session.__state || { open: 0, total: 0, peak: 0 };

    st.open += 1;
    st.total += 1;
    st.peak = Math.max(st.peak, st.open);
    stats.h2Streams += 1;
    stats.peakConcurrentStreams = Math.max(stats.peakConcurrentStreams, st.peak);

    log('📬', 'L7-H2',
      `Stream ${ANSI.bold}#${stream.id}${ANSI.reset} OPENED — HEADERS frame ` +
      `${ANSI.bold}${headers[':method']} ${headers[':path']}${ANSI.reset} ` +
      `${ANSI.grey}(${st.open} stream(s) live on this single TCP connection)${ANSI.reset}`,
      `c#${connId} s#${stream.id}`);

    stream.on('close', () => {
      st.open -= 1;
      log('📪', 'L7-H2',
        `Stream ${ANSI.bold}#${stream.id}${ANSI.reset} CLOSED ` +
        `${ANSI.grey}(${st.open} still live; TCP connection stays UP)${ANSI.reset}`,
        `c#${connId} s#${stream.id}`);
    });
  });

  // ---- The unified request handler (h2 compat + h1) -----------------------
  server.on('request', (req, res) => {
    if (!req.stream) {
      stats.h1Requests += 1;
      const connId = (req.socket && req.socket.__connId) || 0;
      log('📃', 'L7-H1',
        `HTTP/1.1 request ${ANSI.bold}${req.method} ${req.url}${ANSI.reset} ` +
        `${ANSI.grey}(no streams here — this connection is head-of-line blocked until the response completes)${ANSI.reset}`,
        `c#${connId} h1`);
    }
    handleRequest(req, res);
  });

  server.on('sessionError', (err) => log('🔥', 'ERROR', `sessionError: ${err.message}`));
  server.on('clientError', (err, socket) => {
    log('🔥', 'ERROR', `clientError: ${err.message}`);
    if (socket && socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });
  server.on('tlsClientError', (err) => {
    log('🔥', 'L5-TLS', `TLS handshake FAILED: ${err.message} ${ANSI.grey}(client and server found no common ground)${ANSI.reset}`);
  });
  server.on('error', (err) => {
    log('🔥', 'ERROR', `Gateway server error: ${err.message}`);
    if (err.code === 'EADDRINUSE') process.exit(1);
  });

  return server;
}

// ===========================================================================
// SECTION 8 :: BOOTSTRAP
// ===========================================================================

function banner() {
  const line = '═'.repeat(74);
  console.log(`\n${ANSI.cyan}${line}${ANSI.reset}`);
  console.log(`${ANSI.bold}  CoreNet-Proxy${ANSI.reset} — native Node.js L7 reverse proxy & load balancer`);
  console.log(`${ANSI.grey}  TCP/TLS 1.3 termination · ALPN · HTTP/2 multiplexing · Round-Robin LB${ANSI.reset}`);
  console.log(`${ANSI.grey}  node ${process.version} · openssl ${process.versions.openssl} · pid ${process.pid}${ANSI.reset}`);
  console.log(`${ANSI.cyan}${line}${ANSI.reset}\n`);
}

async function main() {
  banner();

  buildPools();

  if (CONFIG.startBackends) {
    log('🚀', 'BOOT', 'Starting internal origin fleet (plaintext HTTP/1.1, loopback only)…');
    try {
      await Promise.all(BACKENDS.map(startBackend));
    } catch (err) {
      log('🔥', 'ERROR', `Origin ${err.backendName} could not bind port ${err.backendPort}: ${err.code || err.message}`);
      if (err.code === 'EADDRINUSE') {
        console.error(`\n  Port ${err.backendPort} is already taken — another CoreNet-Proxy is probably still running.`);
        console.error(`  Find it with:  lsof -nP -iTCP:${err.backendPort} -sTCP:LISTEN`);
        console.error(`  Or start this instance without origins:  node gateway.js --no-backends\n`);
      }
      process.exit(1);
    }
  } else {
    log('⏭️ ', 'BOOT', 'Skipping backends (--no-backends): expecting an external origin fleet.');
  }

  log('🧭', 'BOOT', 'Resolving upstream target names…');
  await resolveTargets(allTargets());

  startHealthChecks();
  log('🩺', 'BOOT', `Active health checker armed — probing /__health every ${CONFIG.healthIntervalMs}ms`);

  if (!CONFIG.startGateway) return;

  const gateway = createGateway();

  gateway.listen(CONFIG.gatewayPort, CONFIG.gatewayHost, () => {
    console.log('');
    log('🛡️ ', 'BOOT',
      `Edge gateway listening on ${ANSI.bold}https://${CONFIG.gatewayHost}:${CONFIG.gatewayPort}${ANSI.reset}`);
    log('🔐', 'BOOT',
      `TLS floor ${ANSI.bold}${CONFIG.minTlsVersion}${ANSI.reset} · ALPN offer ${ANSI.bold}h2, http/1.1${ANSI.reset} · cert ${path.basename(CONFIG.tlsCertPath)}`);
    for (const [name, pool] of pools) {
      log('⚖️ ', 'BOOT',
        `Pool ${ANSI.bold}${name}${ANSI.reset} → ${pool.targets.map((t) => `${t.host}:${t.port}`).join(', ')} ${ANSI.grey}(round-robin)${ANSI.reset}`);
    }
    console.log(`\n${ANSI.grey}  Try:  curl -vk --http2 https://localhost:${CONFIG.gatewayPort}/api/users${ANSI.reset}`);
    console.log(`${ANSI.grey}  Stats: curl -sk https://localhost:${CONFIG.gatewayPort}/__gateway/stats${ANSI.reset}\n`);
  });

  // ---- Graceful shutdown --------------------------------------------------
  let shuttingDown = false;
  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log('');
    log('🛑', 'BOOT', `${signal} received — draining. Gateway stops accepting; in-flight streams finish.`);

    gateway.close(() => log('👋', 'BOOT', 'Gateway socket closed.'));
    for (const [name, st] of backendRuntime) {
      st.server.close(() => log('👋', 'BOOT', `Origin ${name} closed.`));
    }
    for (const pool of pools.values()) pool.agent.destroy();

    // Hard stop if a peer refuses to let go.
    setTimeout(() => {
      log('⛔', 'BOOT', 'Drain timeout — forcing exit.');
      process.exit(0);
    }, 3000).unref();
  };

  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

process.on('unhandledRejection', (err) => log('🔥', 'ERROR', `unhandledRejection: ${err && err.message}`));
process.on('uncaughtException',  (err) => log('🔥', 'ERROR', `uncaughtException: ${err && err.stack}`));

main();
