const express = require('express');
const { NextResponse } = require('next/server');
const app = express();

app.get('/go', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.redirect(req.query.next);
});

app.get('/go2', (req, res) => {
  const target = req.body.returnTo;
  // ruleid: sast.js.open-redirect
  res.redirect(302, target);
});

app.get('/go3', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.location(req.params.dest);
  res.sendStatus(302);
});

app.get('/k', async (ctx) => {
  // ruleid: sast.js.open-redirect
  ctx.redirect(ctx.query.url);
});

async function handler(request, reply) {
  // ruleid: sast.js.open-redirect
  return reply.redirect(request.query.to);
}

app.get('/go4', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.redirect('/' + req.query.path);
});

function middleware(req) {
  // ruleid: sast.js.open-redirect
  return NextResponse.redirect(new URL(req.nextUrl.searchParams.get('next'), req.url));
}

app.get('/hdr', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.setHeader("location", req.query.next);
  // ruleid: sast.js.open-redirect
  res.set("LOCATION", req.query.next);
  res.sendStatus(302);
});

app.get('/wh', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.writeHead(302, { location: req.query.next });
  // ruleid: sast.js.open-redirect
  res.writeHead(302, { Location: req.query.next });
  // ruleid: sast.js.open-redirect
  res.writeHead(302, { "location": req.query.next });
  res.end();
});

app.get('/safe', (req, res) => {
  // ok: sast.js.open-redirect
  res.setHeader("location", "/home");
  // ok: sast.js.open-redirect
  res.writeHead(302, { location: "/home" });
  // ok: sast.js.open-redirect
  res.setHeader("X-Next", req.query.next);
  // ok: sast.js.open-redirect
  res.redirect('/dashboard');
  // ok: sast.js.open-redirect
  res.redirect(302, '/login');
  // ok: sast.js.open-redirect
  res.redirect('/search?q=' + encodeURIComponent(req.query.q));
  // ok: sast.js.open-redirect
  res.redirect('/items/' + req.params.id);
  // ok: sast.js.open-redirect
  res.redirect(process.env.HOME_URL);
});

function safeMiddleware(req) {
  // ok: sast.js.open-redirect
  return NextResponse.redirect(new URL('/login', req.url));
}

app.get('/chained', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.status(302).redirect(req.query.next);
});
app.get('/chained2', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.set('Cache-Control', 'no-store').redirect(req.query.to);
});

app.get('/url-base', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.redirect(new URL('/x', req.query.base));
});

// server-built relative paths and a configured base
app.get('/rel1', (req, res) => {
  // ok: sast.js.open-redirect
  res.redirect(`/items/${req.params.id}`);
});
app.get('/rel2', (req, res) => {
  // ok: sast.js.open-redirect
  res.redirect(`${process.env.BASE_PATH}/items/${req.params.id}`);
});
app.get('/rel3', (req, res) => {
  // ok: sast.js.open-redirect
  res.redirect(config.baseUrl + '/items/' + req.params.id);
});
app.get('/rel4', (req, res) => {
  // ok: sast.js.open-redirect
  res.redirect(BASE_URL + '/u/' + req.query.name);
});
app.get('/rel5', (req, res) => {
  const id = req.params.id;
  if (/^\d+$/.test(id)) {
    // ok: sast.js.open-redirect
    res.redirect('/' + id);
  }
});
app.get('/rel6', (req, res) => {
  const id = req.params.id;
  if (!/^\d+$/.test(id)) {
    return res.sendStatus(400);
  }
  // ok: sast.js.open-redirect
  res.redirect('/' + id);
});
app.get('/rel7', (req, res) => {
  const id = req.params.id;
  if (!/^[0-9]+$/.test(id)) {
    throw new Error('bad id');
  }
  // ok: sast.js.open-redirect
  res.redirect('/' + id);
});

// look-alikes that can still leave the site
app.get('/rel8', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.redirect(`/${req.query.next}`);
});
app.get('/rel9', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.redirect(`//${req.query.host}/x`);
});
app.get('/rel10', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.redirect(`${req.query.base}/items/1`);
});
app.get('/rel11', (req, res) => {
  // the base can be empty, which leaves "/" + the request value
  // ruleid: sast.js.open-redirect
  res.redirect(`${process.env.BASE_PATH}/${req.query.next}`);
});
app.get('/rel12', (req, res) => {
  // a host followed directly by request data can be turned into user@evil.example
  // ruleid: sast.js.open-redirect
  res.redirect(config.baseUrl + req.query.next);
});
app.get('/rel13', (req, res) => {
  // ruleid: sast.js.open-redirect
  res.redirect(req.query.base + '/items/' + req.params.id);
});
app.get('/rel13b', (req, res) => {
  // an empty base followed by "/" + request data can read as //host
  // ruleid: sast.js.open-redirect
  res.redirect(BASE_URL + '/' + req.query.next);
});
// an UPPER_CASE name is trusted only while it is not bound from request data
app.get('/rel15', (req, res) => {
  const BASE_URL = req.query.base;
  // ruleid: sast.js.open-redirect
  res.redirect(BASE_URL + '/items/' + req.params.id);
});
app.get('/rel16', (req, res) => {
  const BASE_URL = req.query.base;
  // ruleid: sast.js.open-redirect
  res.redirect(BASE_URL + '/items/' + 'x');
});
app.get('/rel17', (req, res) => {
  const BASE_URL = req.query.base;
  // known gap (not asserted): a template literal that starts with an UPPER_CASE base is still cleared as a
  // whole, so this request-bound base is missed; the "+" form above is caught
  res.redirect(`${BASE_URL}/items/${req.params.id}`);
});
app.get('/rel17b', (req, res) => {
  // a base that is neither configuration nor a constant name does not clear the tail
  // ruleid: sast.js.open-redirect
  res.redirect(getBase() + '/items/' + req.params.id);
});
app.get('/rel18', (req, res) => {
  const BASE_URL = 'https://app.example.com';
  // ok: sast.js.open-redirect
  res.redirect(BASE_URL + '/items/' + req.params.id);
});
app.get('/rel19', (req, res) => {
  const BASE_URL = process.env.BASE_URL;
  // ok: sast.js.open-redirect
  res.redirect(BASE_URL + '/items/' + req.params.id);
});
app.get('/rel20', (req, res) => {
  const BASE_URL = 'https://app.example.com';
  // ok: sast.js.open-redirect
  res.redirect(`${BASE_URL}/items/${req.params.id}`);
});
app.get('/rel14', (req, res) => {
  const id = req.params.id;
  if (/^[\d/]+$/.test(id)) {
    // ruleid: sast.js.open-redirect
    res.redirect('/' + id);
  }
});
app.get('/rel15', (req, res) => {
  const id = req.params.id;
  if (!/^\d+$/.test(id)) {
    console.warn('odd id');
  }
  // ruleid: sast.js.open-redirect
  res.redirect('/' + id);
});
app.get('/rel16', (req, res) => {
  const id = req.params.id;
  const next = req.query.next;
  if (/^\d+$/.test(id)) {
    // ruleid: sast.js.open-redirect
    res.redirect(next);
  }
});
