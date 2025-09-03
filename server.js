import express from 'express';
import http from 'http';
import compression from 'compression';
import morgan from 'morgan';
import httpProxy from 'http-proxy';
import rateLimit from 'express-rate-limit';
import { URL } from 'url';

const app = express();
const server = http.createServer(app);

// Config via env
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const BASE_UPSTREAM = process.env.BASE_UPSTREAM || '';
const PROXY_USER = process.env.PROXY_USER || '';
const PROXY_PASS = process.env.PROXY_PASS || '';
const ALLOWLIST = (process.env.ALLOWLIST || '').split(',').map(s => s.trim()).filter(Boolean);
const ENABLE_CORS = (process.env.ENABLE_CORS || 'false').toLowerCase() === 'true';
const MAX_REDIRECTS = 10;

// Middleware
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
  if (!ALLOWLIST.length) return true;
  return ALLOWLIST.includes(hostname);
}

function resolveTarget(req) {
  if (BASE_UPSTREAM) {
    const upstream = new URL(BASE_UPSTREAM);
    const joined = new URL(req.originalUrl, upstream);
    joined.pathname = req.path;
    joined.search = req.url.split('?')[1] ? '?' + req.url.split('?')[1] : '';
    return joined;
  }
  const q = req.query.url;
  if (!q) return null;
  try { return new URL(q); } catch { return null; }
}

const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  secure: true,
  ws: true,
  xfwd: true,
  selfHandleResponse: true // needed for internal redirect handling
});

function handleProxy(req, res, targetUrl, redirectCount = 0) {
  if (redirectCount > MAX_REDIRECTS) {
    return res.status(508).json({ error: 'Too many redirects' });
  }

  res.locals.__targetUrl = targetUrl;
  if (BASE_UPSTREAM) {
    req.url = targetUrl.pathname + targetUrl.search;
  }
  req.headers.host = targetUrl.host;

  proxy.once('proxyRes', (proxyRes, req2, res2) => {
    const status = proxyRes.statusCode;
    const selfOrigin = `${req2.protocol}://${req2.headers['x-forwarded-host'] || req2.headers.host}`;

    // Rewrite cookies
    const setCookie = proxyRes.headers['set-cookie'];
    if (setCookie && Array.isArray(setCookie)) {
      proxyRes.headers['set-cookie'] = setCookie.map(cookie =>
        cookie
          .replace(/;\s*Domain=[^;]*/i, `; Domain=${new URL(selfOrigin).hostname}`)
          .replace(/;\s*Path=[^;]*/i, `; Path=/`)
      );
    }

    // Handle redirects internally
    if ([301, 302, 303, 307, 308].includes(status) && proxyRes.headers.location) {
      try {
        const abs = new URL(proxyRes.headers.location, targetUrl);
        if (!isAllowedHost(abs.hostname)) {
          return res2.status(403).json({ error: 'Redirect target not allowed' });
        }
        if (status === 303) {
          req2.method = 'GET';
          req2.body = null;
        }
        return handleProxy(req2, res2, abs, redirectCount + 1);
      } catch {
        return res2.status(502).json({ error: 'Invalid redirect URL' });
      }
    }

    // Pass through non-redirect response
    Object.entries(proxyRes.headers).forEach(([k, v]) => res2.setHeader(k, v));
    proxyRes.pipe(res2);
  });

  proxy.web(req, res, {
    target: `${targetUrl.protocol}//${targetUrl.host}`,
    prependPath: false,
    ignorePath: !BASE_UPSTREAM,
    secure: true
  });
}

proxy.on('error', (err, req, res) => {
  if (!res.headersSent) {
    res.status(502).json({ error: 'Upstream proxy error', detail: err.message });
  }
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));
app.use(basicAuth);

app.all(['/proxy', '/proxy/*'], (req, res) => {
  const targetUrl = resolveTarget(req);
  if (!targetUrl) return res.status(400).json({ error: 'Missing or invalid url. Provide ?url=...' });
  if (!/^https?:$/.test(targetUrl.protocol)) return res.status(400).json({ error: 'Only http and https are supported' });
  if (!isAllowedHost(targetUrl.hostname)) return res.status(403).json({ error: 'Target host not allowed' });
  handleProxy(req, res, targetUrl);
});

if (BASE_UPSTREAM) {
  app.all('*', (req, res, next) => {
    req.query.url = new URL(req.originalUrl, BASE_UPSTREAM).toString();
    return app._router.handle(req, res, next);
  });
}

server.on('upgrade', (req, socket, head) => {
  let targetUrl = null;
  try {
    if (BASE_UPSTREAM) {
      targetUrl = new URL(req.url, new URL(BASE_UPSTREAM));
    } else {
      const u = new URL(req.url, 'http://placeholder');
      const q = u.searchParams.get('url');
      if (!q) return socket.destroy();
      targetUrl = new URL(q);
    }
  } catch { return socket.destroy(); }

  if (!/^https?:$/.test(targetUrl.protocol) || !isAllowedHost(targetUrl.hostname)) {
    return socket.destroy();
  }

  proxy.ws(req, socket, head, {
    target: `${targetUrl.protocol}//${targetUrl.host}`,
    secure: true
  });
});

server.listen(PORT, () => {
  console.log(`Proxy listening on :${PORT}`);
  console.log(BASE_UPSTREAM
    ? `Reverse proxy mode → ${BASE_UPSTREAM}`
    : `URL mode → GET /proxy?url=https://example.com`);
});
