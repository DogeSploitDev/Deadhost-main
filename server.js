import express from 'express';
import http from 'http';
import { URL } from 'url';
import compression from 'compression';
import morgan from 'morgan';
import httpProxy from 'http-proxy';
import rateLimit from 'express-rate-limit';
import { StringDecoder } from 'string_decoder';

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const BASE_UPSTREAM = process.env.BASE_UPSTREAM || '';
const PROXY_USER = process.env.PROXY_USER || '';
const PROXY_PASS = process.env.PROXY_PASS || '';
const ALLOWLIST = (process.env.ALLOWLIST || '').split(',').map(s => s.trim()).filter(Boolean);
const ENABLE_CORS = (process.env.ENABLE_CORS || 'false').toLowerCase() === 'true';

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
  xfwd: true,
  selfHandleResponse: true // so we can rewrite HTML
});

proxy.on('proxyRes', (proxyRes, req, res) => {
  const target = res.locals.__targetUrl;
  const selfOrigin = `${req.protocol}://${req.headers['x-forwarded-host'] || req.headers.host}`;

  // Rewrite cookies
  const setCookie = proxyRes.headers['set-cookie'];
  if (setCookie && Array.isArray(setCookie)) {
    proxyRes.headers['set-cookie'] = setCookie.map((cookie) => {
      return cookie
        .replace(/;\s*Domain=[^;]*/i, `; Domain=${new URL(selfOrigin).hostname}`)
        .replace(/;\s*Path=[^;]*/i, `; Path=/`);
    });
  }

  // Rewrite redirects
  const loc = proxyRes.headers['location'];
  if (loc && target) {
    try {
      const abs = new URL(loc, target);
      if (BASE_UPSTREAM) {
        proxyRes.headers['location'] = `${selfOrigin}${abs.pathname}${abs.search}`;
      } else {
        proxyRes.headers['location'] = `${selfOrigin}/?url=${encodeURIComponent(abs.toString())}`;
      }
    } catch {}
  }

  // HTML rewriting
  const contentType = proxyRes.headers['content-type'] || '';
  if (contentType.includes('text/html')) {
    let body = '';
    const decoder = new StringDecoder('utf8');
    proxyRes.on('data', chunk => { body += decoder.write(chunk); });
    proxyRes.on('end', () => {
      body += decoder.end();
      body = body.replace(/(href|src|action)=["']([^"']+)["']/gi, (m, attr, url) => {
        try {
          const abs = new URL(url, target);
          if (BASE_UPSTREAM) {
            return `${attr}="${selfOrigin}${abs.pathname}${abs.search}"`;
          } else {
            return `${attr}="/?url=${encodeURIComponent(abs.toString())}"`;
          }
        } catch {
          return m;
        }
      });
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      res.end(body);
    });
  } else {
    // Non-HTML: stream directly
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  }
});

proxy.on('error', (err, req, res) => {
  if (!res.headersSent) {
    res.status(502).json({ error: 'Upstream proxy error', detail: err.message });
  }
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));

app.use(basicAuth);

// Catch-all proxy
app.all('*', (req, res) => {
  let targetUrl = resolveTarget(req);

  if (!targetUrl && !BASE_UPSTREAM) {
    const q = req.query.url || req.originalUrl;
    try {
      targetUrl = new URL(q.startsWith('http') ? q : `http://${q}`);
    } catch {
      return res.status(400).json({ error: 'Invalid target URL' });
    }
  }

  if (!targetUrl) return res.status(400).json({ error: 'No target URL' });
  if (!/^https?:$/.test(targetUrl.protocol)) return res.status(400).json({ error: 'Unsupported protocol' });
  if (!isAllowedHost(targetUrl.hostname)) return res.status(403).json({ error: 'Host not allowed' });

  res.locals.__targetUrl = targetUrl;
  req.headers.host = targetUrl.host;

  proxy.web(req, res, {
    target: `${targetUrl.protocol}//${targetUrl.host}`,
    prependPath: false,
    ignorePath: !BASE_UPSTREAM,
    secure: true
  });
});

// WebSocket upgrades
server.on('upgrade', (req, socket, head) => {
  let targetUrl = null;
  if (BASE_UPSTREAM) {
    try {
      const base = new URL(BASE_UPSTREAM);
      targetUrl = new URL(req.url, base);
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
    console.log(`URL mode → /?url=https://example.com`);
  }
});
