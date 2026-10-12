const _ = require('lodash');
const express = require('express');
const app = express();

app.post('/set', (req, res) => {
  const config = {};
  // ruleid: sast.js.prototype-pollution
  config[req.body.section][req.body.key] = req.body.value;
  res.json(config);
});

app.post('/nested', (req, res) => {
  const { a, b, v } = req.body;
  const store = {};
  // ruleid: sast.js.prototype-pollution
  store[a][b] = v;
  res.json(store);
});

app.post('/loop', (req, res) => {
  const target = {};
  for (const key of Object.keys(req.body)) {
    // ruleid: sast.js.prototype-pollution
    target[key] = req.body[key];
  }
  res.json(target);
});

app.post('/loop2', (req, res) => {
  const target = {};
  // ruleid: sast.js.prototype-pollution
  Object.keys(req.query).forEach((k) => {
    target[k] = req.query[k];
  });
  res.json(target);
});

app.post('/merge', (req, res) => {
  const defaults = { theme: 'light' };
  // ruleid: sast.js.prototype-pollution
  _.merge(defaults, req.body);
  // ruleid: sast.js.prototype-pollution
  _.defaultsDeep({}, req.body.settings);
  // ruleid: sast.js.prototype-pollution
  _.set(defaults, req.query.path, 1);
  // ruleid: sast.js.prototype-pollution
  _.zipObjectDeep(req.body.paths, [1, 2]);
  res.json(defaults);
});

app.post('/safe', (req, res) => {
  const out = {};
  // ok: sast.js.prototype-pollution
  out[req.body.key] = 1;
  const grid = [[0, 0], [0, 0]];
  for (let i = 0; i < 2; i++) {
    // ok: sast.js.prototype-pollution
    grid[i][i] = 1;
  }
  const fixed = ['a', 'b'];
  for (const k of fixed) {
    // ok: sast.js.prototype-pollution
    out[k] = req.body[k];
  }
  // ok: sast.js.prototype-pollution
  _.merge({}, { a: 1 }, { b: 2 });
  // ok: sast.js.prototype-pollution
  _.merge(out, _.pick(req.body, ['name', 'email']));
  // ok: sast.js.prototype-pollution
  _.set(out, 'profile.name', req.body.name);
  res.json(out);
});
