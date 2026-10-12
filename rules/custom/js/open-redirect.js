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

app.get('/safe', (req, res) => {
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
