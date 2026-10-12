const axios = require('axios');
const got = require('got');
const https = require('https');
const express = require('express');
const app = express();

app.get('/proxy', async (req, res) => {
  // ruleid: sast.js.ssrf
  const r = await fetch(req.query.url);
  res.send(await r.text());
});

app.post('/hook', async (req, res) => {
  const target = req.body.callback;
  // ruleid: sast.js.ssrf
  const r = await axios.get(target);
  res.json(r.data);
});

app.get('/g', async (req, res) => {
  // ruleid: sast.js.ssrf
  const r = await got(`http://${req.query.host}/status`);
  res.send(r.body);
});

app.get('/https', (req, res) => {
  // ruleid: sast.js.ssrf
  https.get(req.query.u, (up) => up.pipe(res));
  // ruleid: sast.js.ssrf
  axios({ method: 'post', url: req.body.endpoint, data: {} });
  // ruleid: sast.js.ssrf
  fetch(encodeURI(req.query.url));
  res.end();
});

app.get('/safe', async (req, res) => {
  // ok: sast.js.ssrf
  const a = await fetch('https://api.example.com/items?id=' + encodeURIComponent(req.query.id));
  // ok: sast.js.ssrf
  const b = await axios.get('https://api.example.com/users/' + req.params.id);
  // ok: sast.js.ssrf
  const c = await axios.get('https://api.example.com/health');
  // ok: sast.js.ssrf
  const d = await fetch(process.env.UPSTREAM_URL);
  // ok: sast.js.ssrf
  const e = new Map().get(req.query.key);
  // ok: sast.js.ssrf
  const f = await axios.post('https://api.example.com/log', { note: req.body.note });
  res.json([a, b, c, d, e, f]);
});
