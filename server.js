import express from 'express';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import compression from 'compression';
import morgan from 'morgan';
import httpProxy from 'http-proxy';
import rateLimit from 'express-rate-limit';

const app = express();
const server = http.createServer(app);

// Config via env
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';

// Mode A: reverse proxy a single upstream (set BASE_UPSTREAM to enable)
// e.g., BASE_UPSTREAM=https://example.com
const BASE_UPSTREAM = process.env.BASE_UPSTREAM || '';

// Mode B: on-demand proxy via `?url=` when BASE_UPSTREAM is empty
// Optional Basic Auth for protection
const PROXY_USER = process.env.PROXY_USER || '';
const PROXY_PASS = process.env.PROXY_PASS || '';

// Optional comma-separated allowlist of hostnames to proxy
// e.g., ALLOWLIST=api.github.com,example.com
const ALLOWLIST = (process.env.ALLOWLIST || '').split(',').map(s => s.trim()).filter(Boolean);

// CORS for API use (disable for pure website proxy)
const ENABLE_CORS = (process.env.ENABLE_CORS || 'false').toLowerCase() === 'true';

// Basic rate limit (tune to your needs)
const limiter = rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

app.use(limiter);
app.use(compression());
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.raw({ type: '*/*', limit: '20mb' }));

if (ENABLE_CORS) {
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', req.header('Access-Control-Request-Headers') || '*');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });
}

function basicAuth(req, res, next) {
  if (!PROXY_USER) return next();
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Basic ') ? hdr.slice(6) : '';
  const [u, p] = Buffer.from(token, 'base64').toString('utf8').split(':');
  if (u === PROXY_USER && p === PROXY_PASS) return next();
  res.setHeader('WWW-Authenticate', 'Basic realm="Proxy"');
  return res.status(401).send('Authentication required');
}

function isAllowedHost(hostname) {
  if (!ALLOWLIST.length) return true; // no allowlist → allow all
  return ALLOWLIST.includes(hostname);
}

function resolveTarget(req) {
  // Mode A: single upstream
  if (BASE_UPSTREAM) {
    const upstream = new URL(BASE_UPSTREAM);
    // Preserve original path and query
    const joined = new URL(req.originalUrl, upstream);
    // originalUrl includes the path; we want to map "/" of our app to upstream "/"
    // For clean mapping, strip our origin part:
    joined.pathname = req.path;
    joined.search = req.url.split('?')[1] ? '?' + req.url.split('?')[1] : '';
    return joined;
  }
  // Mode B: url query param
  const q = req.query.url;
  if (!q) return null;
  try {
    return new URL(q);
  } catch {
    return null;
  }
}

const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  secure: true,
  ws: true,
  xfwd: true
});

// Safety + polish on proxied response
proxy.on('proxyRes', (proxyRes, req, res) => {
  const target = res.locals.__targetUrl;
  const selfOrigin = `${req.protocol}://${req.headers['x-forwarded-host'] || req.headers.host}`;

  // Rewrite Set-Cookie Domain and Path to current host
  const setCookie = proxyRes.headers['set-cookie'];
  if (setCookie && Array.isArray(setCookie)) {
    proxyRes.headers['set-cookie'] = setCookie.map((cookie) => {
      let c = cookie
        .replace(/;\s*Domain=[^;]*/i, `; Domain=${new URL(selfOrigin).hostname}`)
        .replace(/;\s*Path=[^;]*/i, `; Path=/`);
      return c;
    });
  }

  // Rewrite Location redirects to stay within the proxy
  const loc = proxyRes.headers['location'];
  if (loc && target) {
    try {
      const abs = new URL(loc, target);
      // If redirect points to target's origin, map back through proxy entry
      if (abs.origin === target.origin) {
        if (BASE_UPSTREAM) {
          proxyRes.headers['location'] = `${selfOrigin}${abs.pathname}${abs.search}`;
        } else {
          proxyRes.headers['location'] = `${selfOrigin}/proxy?url=${encodeURIComponent(abs.toString())}`;
        }
      }
    } catch {
      // leave as-is
    }
  }

  // Optional: loosen CSP for embedding (comment out if not needed)
  // if (proxyRes.headers['content-security-policy']) {
  //   delete proxyRes.headers['content-security-policy'];
  // }
});

// Robust error handling
proxy.on('error', (err, req, res) => {
  if (!res.headersSent) {
    res.status(502).json({ error: 'Upstream proxy error', detail: err.message });
  }
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));

app.use(basicAuth);

// Main proxy route(s)
app.all(['/proxy', '/proxy/*'], (req, res) => {
  const targetUrl = resolveTarget(req);
  if (!targetUrl) return res.status(400).json({ error: 'Missing or invalid url. Provide ?url=...' });

  if (!/^https?:$/.test(targetUrl.protocol)) {
    return res.status(400).json({ error: 'Only http and https are supported' });
  }

  if (!isAllowedHost(targetUrl.hostname)) {
    return res.status(403).json({ error: 'Target host not allowed' });
  }

  res.locals.__targetUrl = targetUrl;

  // For transparent path mapping in reverse mode, adjust req.url only in Mode A
  if (BASE_UPSTREAM) {
    req.url = targetUrl.pathname + targetUrl.search;
  }

  // Tweak headers to look like a normal browser if needed
  req.headers.host = targetUrl.host;

  proxy.web(req, res, {
    target: `${targetUrl.protocol}//${targetUrl.host}`,
    prependPath: false,
    ignorePath: !BASE_UPSTREAM, // in URL mode, we already pass the full URL
    selfHandleResponse: false,
    secure: true
  });
});

// Root mapping in reverse mode (optional convenience)
if (BASE_UPSTREAM) {
  app.all('*', (req, res, next) => {
    req.query.url = new URL(req.originalUrl, BASE_UPSTREAM).toString();
    return app._router.handle(req, res, next);
  });
}

// Websocket upgrades
server.on('upgrade', (req, socket, head) => {
  let targetUrl = null;

  if (BASE_UPSTREAM) {
    try {
      const base = new URL(BASE_UPSTREAM);
      const joined = new URL(req.url, base);
      targetUrl = joined;
    } catch {
      socket.destroy();
      return;
    }
  } else {
    try {
      const u = new URL(req.url, 'http://placeholder');
      const q = u.searchParams.get('url');
      if (!q) { socket.destroy(); return; }
      targetUrl = new URL(q);
    } catch {
      socket.destroy();
      return;
    }
  }

  if (!/^https?:$/.test(targetUrl.protocol) || !isAllowedHost(targetUrl.hostname)) {
    socket.destroy();
    return;
  }

  proxy.ws(req, socket, head, {
    target: `${targetUrl.protocol}//${targetUrl.host}`,
    secure: true
  });
});

server.listen(PORT, () => {
  console.log(`Proxy listening on :${PORT}`);
  if (BASE_UPSTREAM) {
    console.log(`Reverse proxy mode → ${BASE_UPSTREAM}`);
  } else {
    console.log(`URL mode → GET /proxy?url=https://example.com`);
  }
});
