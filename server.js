// server.js - Universal-enhanced proxy (drop-in replacement)
// Requires: npm i express compression morgan http-proxy express-rate-limit cheerio raw-body
import express from 'express';
import http from 'http';
import compression from 'compression';
import morgan from 'morgan';
import httpProxy from 'http-proxy';
import rateLimit from 'express-rate-limit';
import { URL } from 'url';
import zlib from 'zlib';
import getRawBody from 'raw-body';
import * as cheerio from 'cheerio'

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
const SPOOF_ORIGIN = (process.env.SPOOF_ORIGIN || 'false').toLowerCase() === 'true';
const MAX_REDIRECTS = 10;

// small marker to avoid double-injecting
const INJECT_MARKER = '<!--__PROXY_CLIENT_PATCH__-->';

// client-side patch that reroutes fetch/XHR/WebSocket and guards against double-proxying
const CLIENT_PATCH = `\n${INJECT_MARKER}\n<script>(function(){\n  try{\n    const proxyBase = location.origin + '/proxy?url=';\n    function shouldProxyUrl(url){\n      try{\n        const abs = new URL(url, location.href);\n        // do not proxy same-origin or our proxy endpoints\n        if (abs.origin === location.origin) return false;\n        // avoid proxying about:, data:, blob:, filesystem:, mailto:, tel:\n        if (/^(about|data|blob|filesystem|mailto|tel):/i.test(abs.protocol)) return false;\n        return true;\n      }catch(e){return false;}\n    }\n    function proxify(url){\n      try{\n        if (!shouldProxyUrl(url)) return url;\n        const abs = new URL(url, location.href);\n        return proxyBase + encodeURIComponent(abs.href);\n      }catch(e){return url;}\n    }\n\n    // patch fetch\n    const origFetch = window.fetch.bind(window);\n    window.fetch = function(input, init){\n      try{\n        if (typeof input === 'string'){ input = proxify(input); }\n        else if (input instanceof Request){ input = new Request(proxify(input.url), input); }\n      }catch(e){}\n      return origFetch(input, init);\n    };\n\n    // patch XHR\n    const origOpen = XMLHttpRequest.prototype.open;\n    XMLHttpRequest.prototype.open = function(method, url, async, user, password){\n      try{ url = proxify(url); }catch(e){}\n      return origOpen.apply(this, [method, url, async, user, password]);\n    };\n\n    // patch WebSocket (ws and wss -> http(s) proxy mapping)\n    const OrigWS = window.WebSocket;\n    window.WebSocket = function(url, protocols){\n      try{\n        if (shouldProxyUrl(url)){\n          // convert ws:// -> http:// and wss:// -> https:// for proxy param\n          const u = new URL(url, location.href);\n          return new OrigWS(proxyBase + encodeURIComponent(u.href), protocols);\n        }\n      }catch(e){}\n      return new OrigWS(url, protocols);\n    };\n\n    // history API patch to rewrite pushState/replaceState navigations to pass through proxy\n    const origPush = history.pushState;\n    history.pushState = function(state, title, url){\n      try{ if (url) url = proxify(url); }catch(e){}\n      return origPush.call(history, state, title, url);\n    };\n    const origReplace = history.replaceState;\n    history.replaceState = function(state, title, url){\n      try{ if (url) url = proxify(url); }catch(e){}\n      return origReplace.call(history, state, title, url);\n    };\n\n    // Prevent double-injection by setting a flag\n    window.__proxy_client_patched = true;\n  }catch(e){/* swallowing to avoid breaking site */}\n})();</script>\n`;

// Middleware & utilities
const limiter = rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});
app.use(limiter);
app.use(compression());
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.raw({ type: '*/*', limit: '50mb' }));

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
  res.setHeader('WWW-Authenticate', 'Basic realm=\"Proxy\"');
  return res.status(401).send('Authentication required');
}

function isAllowedHost(hostname) {
  if (!ALLOWLIST.length) return true;
  return ALLOWLIST.includes(hostname);
}

function resolveTarget(req) {
  if (BASE_UPSTREAM) {
    const upstream = new URL(BASE_UPSTREAM);
    return new URL(req.originalUrl, upstream);
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
  selfHandleResponse: true
});

// attach target URL to req for use in proxy events
function attachTargetToReq(req, targetUrl) {
  req._targetUrl = targetUrl;
}

proxy.on('proxyReq', function(proxyReq, req, res, options) {
  try {
    const target = req._targetUrl;
    if (!target) return;
    // Optionally spoof Origin/Referer to the target origin for compat
    if (SPOOF_ORIGIN) {
      proxyReq.setHeader('origin', target.origin);
      if (req.headers.referer) proxyReq.setHeader('referer', target.href);
    }
    // remove hop-by-hop headers that may leak local info
    proxyReq.removeHeader('accept-encoding'); // we handle compression ourselves
  } catch (e) {}
});

// helper: build proxy URL (where user should click) given a target URL
function buildProxyUrl(targetUrl, req) {
  if (BASE_UPSTREAM) {
    const selfOrigin = `${req.protocol}://${req.get('host')}`;
    const proxiedPath = targetUrl.pathname + (targetUrl.search || '');
    return selfOrigin + proxiedPath;
  } else {
    const selfOrigin = `${req.protocol}://${req.get('host')}`;
    return `${selfOrigin}/proxy?url=${encodeURIComponent(targetUrl.toString())}`;
  }
}

// rewrite Set-Cookie to work with proxy host
function rewriteSetCookie(setCookieArr) {
  if (!setCookieArr) return;
  return setCookieArr.map(cookie => {
    let c = cookie.replace(/;\\s*Domain=[^;]*/i, '').replace(/;\\s*Path=[^;]*/i, '');
    if (!/;\\s*Path=/i.test(c)) c += '; Path=/';
    return c;
  });
}

function rewriteLocationHeader(loc, upstreamUrl, req) {
  try {
    const abs = new URL(loc, upstreamUrl);
    if (!isAllowedHost(abs.hostname)) return null;
    return buildProxyUrl(abs, req);
  } catch {
    return null;
  }
}

// HTML rewriting to proxify links/forms/meta/css url() etc.
function rewriteHtml(bodyStr, upstreamUrl, req) {
  // avoid double injecting
  if (bodyStr.includes(INJECT_MARKER)) {
    // still rewrite links to be safe
  }

  const $ = cheerio.load(bodyStr, { decodeEntities: false });
  const baseHref = $('base').attr('href') || upstreamUrl.origin;

  function absUrl(href) {
    try { return new URL(href, baseHref); } catch { return null; }
  }

  // anchors
  $('a[href]').each((i, el) => {
    const $el = $(el);
    const href = $el.attr('href');
    if (!href) return;
    if (/^\\s*(javascript:|mailto:|tel:|#)/i.test(href)) return;
    const abs = absUrl(href);
    if (!abs) return;
    if (!isAllowedHost(abs.hostname)) {
      $el.attr('target','_blank');
      $el.attr('rel','noreferrer noopener');
      $el.attr('href','#');
      return;
    }
    $el.attr('href', buildProxyUrl(abs, req));
  });

  // forms (action attribute)
  $('form[action]').each((i, el) => {
    const $el = $(el);
    const action = $el.attr('action');
    if (!action) return;
    if (/^\\s*(javascript:|#)/i.test(action)) return;
    const abs = absUrl(action);
    if (!abs) return;
    if (!isAllowedHost(abs.hostname)) {
      $el.attr('action', '');
      return;
    }
    $el.attr('action', buildProxyUrl(abs, req));
  });

  // meta refresh
  $('meta[http-equiv]').each((i, el) => {
    const $el = $(el);
    if ($el.attr('http-equiv').toLowerCase() !== 'refresh') return;
    const content = $el.attr('content') || '';
    const match = content.match(/^\\s*([^;]+);\\s*url=(.+)$/i);
    if (!match) return;
    const seconds = match[1];
    const urlPart = match[2].trim().replace(/^['"]|['"]$/g, '');
    const abs = absUrl(urlPart);
    if (!abs) return;
    if (!isAllowedHost(abs.hostname)) {
      $el.attr('content', `${seconds};url=#`);
      return;
    }
    $el.attr('content', `${seconds};url=${buildProxyUrl(abs, req)}`);
  });

  // inline CSS url(...) and link[href] for stylesheets / images
  $('[style]').each((i, el) => {
    const s = $(el).attr('style');
    if (!s) return;
    const replaced = s.replace(/url\\((['"]?)([^'")]+)\\1\\)/g, (_, _q, url) => {
      const abs = absUrl(url);
      if (!abs || !isAllowedHost(abs.hostname)) return `url(#)`;
      return `url(${buildProxyUrl(abs, req)})`;
    });
    $(el).attr('style', replaced);
  });

  $('link[href]').each((i, el) => {
    const $el = $(el);
    const href = $el.attr('href');
    if (!href) return;
    const abs = absUrl(href);
    if (!abs) return;
    if (!isAllowedHost(abs.hostname)) {
      $el.attr('href', '#');
      return;
    }
    $el.attr('href', buildProxyUrl(abs, req));
  });

  $('img[src]').each((i, el) => {
    const $el = $(el);
    const src = $el.attr('src');
    const abs = absUrl(src);
    if (!abs) return;
    if (!isAllowedHost(abs.hostname)) {
      $el.attr('src', '');
      return;
    }
    $el.attr('src', buildProxyUrl(abs, req));
  });

  $('script[src]').each((i, el) => {
    const $el = $(el);
    const src = $el.attr('src');
    const abs = absUrl(src);
    if (!abs) return;
    if (!isAllowedHost(abs.hostname)) {
      $el.attr('src', '');
      return;
    }
    $el.attr('src', buildProxyUrl(abs, req));
  });

  // inject client patch at end of body if not present
  try {
    if (!$('body').length) {
      $('html').append('<body></body>');
    }
    const bodyHtml = $('body').html() || '';
    if (!bodyHtml.includes(INJECT_MARKER)) {
      $('body').append(CLIENT_PATCH);
    }
  } catch (e) {}

  return $.html();
}

// Handle proxied responses (selfHandleResponse = true)
async function handleProxy(req, res, targetUrl) {
  if (!isAllowedHost(targetUrl.hostname)) return res.status(403).json({ error: 'Target host not allowed' });

  // attach for proxy events
  attachTargetToReq(req, targetUrl);

  // prepare proxied request options
  req.headers.host = targetUrl.host;

  proxy.once('proxyRes', async (proxyRes, req2, res2) => {
    try {
      const status = proxyRes.statusCode;

      // rewrite set-cookie
      if (proxyRes.headers['set-cookie']) {
        const newCookies = rewriteSetCookie(proxyRes.headers['set-cookie']);
        if (newCookies) res2.setHeader('set-cookie', newCookies);
      }

      // Handle redirects by rewriting Location to route back through proxy
      if ([301,302,303,307,308].includes(status) && proxyRes.headers.location) {
        const rewritten = rewriteLocationHeader(proxyRes.headers.location, targetUrl, req2);
        if (!rewritten) return res2.status(403).json({ error: 'Redirect target not allowed' });
        res2.setHeader('location', rewritten);
        return res2.status(status).end();
      }

      const contentType = (proxyRes.headers['content-type'] || '').toLowerCase();
      const isHtml = contentType.includes('text/html');
      const isText = contentType.startsWith('text/') || contentType.includes('json') || contentType.includes('javascript') || isHtml;

      // For non-text (images, video etc.) stream directly
      if (!isText) {
        // copy headers but strip security headers that could block proxy
        Object.entries(proxyRes.headers).forEach(([k,v])=>{
          const lk = k.toLowerCase();
          if (['content-length'].includes(lk)) return; // let node handle length via pipe
          if (['content-security-policy','x-frame-options','strict-transport-security','content-security-policy-report-only'].includes(lk)) return;
          res2.setHeader(k,v);
        });
        res2.status(proxyRes.statusCode);
        proxyRes.pipe(res2);
        return;
      }

      // For text responses buffer and modify
      const encoding = (proxyRes.headers['content-encoding'] || '').toLowerCase();
      const bodyBuf = await getRawBody(proxyRes);
      let bodyStr = bodyBuf.toString('utf8');

      if (encoding === 'gzip') bodyStr = zlib.gunzipSync(bodyBuf).toString('utf8');
      else if (encoding === 'deflate') bodyStr = zlib.inflateSync(bodyBuf).toString('utf8');
      else if (encoding === 'br') { try { bodyStr = zlib.brotliDecompressSync(bodyBuf).toString('utf8'); } catch (e){} }

      // rewrite HTML or replace absolute upstream origins in JS/JSON/text
      let outStr = bodyStr;
      if (isHtml) {
        outStr = rewriteHtml(bodyStr, targetUrl, req2);
      } else {
        // conservative replacement of upstream origin occurrences (quoted)
        try {
          const upstreamOrigin = targetUrl.origin;
          outStr = bodyStr.replace(new RegExp(upstreamOrigin.replace(/[-/\\\\^$*+?.()|[\\]{}]/g, '\\\\$&') + '([^\"' + "'\\\\s\\\\)\\\\]]*)", 'g'), (m, rest) => {
            try{
              const abs = new URL(upstreamOrigin + rest);
              if (!isAllowedHost(abs.hostname)) return m;
              return buildProxyUrl(abs, req2);
            }catch(e){ return m; }
          });
        } catch (e) { outStr = bodyStr; }
      }

      // recompress if needed
      let bufferOut = Buffer.from(outStr, 'utf8');
      if (encoding === 'gzip') bufferOut = zlib.gzipSync(bufferOut);
      else if (encoding === 'deflate') bufferOut = zlib.deflateSync(bufferOut);
      else if (encoding === 'br') { try { bufferOut = zlib.brotliCompressSync(bufferOut); } catch (e){} }

      // copy headers but strip blocking CSP/XFO headers and update content-length/encoding
      Object.entries(proxyRes.headers).forEach(([k,v])=>{
        const lk = k.toLowerCase();
        if (['content-length','content-encoding','location'].includes(lk)) return;
        if (['content-security-policy','x-frame-options','strict-transport-security','content-security-policy-report-only'].includes(lk)) return;
        res2.setHeader(k,v);
      });

      if (encoding) res2.setHeader('content-encoding', encoding);
      res2.setHeader('content-length', bufferOut.length);
      res2.setHeader('x-proxied-by','universal-enhanced-proxy');

      res2.status(proxyRes.statusCode).end(bufferOut);
    } catch (err) {
      if (!res2.headersSent) res2.status(502).json({ error: 'Response handling error', detail: err.message });
    }
  });

  // Proxy the request
  proxy.web(req, res, {
    target: `${targetUrl.protocol}//${targetUrl.host}`,
    prependPath: false,
    ignorePath: !BASE_UPSTREAM,
    secure: true
  });
}

proxy.on('error', (err, req, res) => {
  try{ if (!res.headersSent) res.status(502).json({ error: 'Upstream proxy error', detail: err.message }); }catch(e){}
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));
app.use(basicAuth);

app.all(['/proxy', '/proxy/*'], (req, res) => {
  const targetUrl = resolveTarget(req);
  if (!targetUrl) return res.status(400).json({ error: 'Missing or invalid url. Provide ?url=...' });
  if (!/^https?:$/.test(targetUrl.protocol)) return res.status(400).json({ error: 'Only http and https are supported' });
  if (!isAllowedHost(targetUrl.hostname)) return res.status(403).json({ error: 'Target host not allowed' });
  return handleProxy(req, res, targetUrl);
});

if (BASE_UPSTREAM) {
  app.all('*', (req, res) => {
    try {
      const t = new URL(req.originalUrl, BASE_UPSTREAM);
      return handleProxy(req, res, t);
    } catch { return res.status(400).json({ error: 'Bad upstream mapping' }); }
  });
}

// Websocket upgrade handling
server.on('upgrade', (req, socket, head) => {
  let targetUrl = null;
  try {
    if (BASE_UPSTREAM) targetUrl = new URL(req.url, new URL(BASE_UPSTREAM));
    else {
      const u = new URL(req.url, 'http://placeholder');
      const q = u.searchParams.get('url');
      if (!q) return socket.destroy();
      targetUrl = new URL(q);
    }
  } catch { return socket.destroy(); }

  if (!/^https?:$/.test(targetUrl.protocol) || !isAllowedHost(targetUrl.hostname)) return socket.destroy();

  proxy.ws(req, socket, head, {
    target: `${targetUrl.protocol}//${targetUrl.host}`,
    secure: true
  });
});

server.listen(PORT, () => {
  console.log(`Universal enhanced proxy listening on :${PORT}`);
  console.log(BASE_UPSTREAM ? `Reverse proxy mode → ${BASE_UPSTREAM}` : `URL mode → GET /proxy?url=https://example.com`);
});
