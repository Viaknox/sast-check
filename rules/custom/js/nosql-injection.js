const express = require('express');
const mongoSanitize = require('mongo-sanitize');
const User = require('./models/user');
const app = express();

app.post('/login', async (req, res) => {
  // ruleid: sast.js.nosql-injection
  const u = await User.findOne({ email: req.body.email, password: req.body.password });
  res.json(u);
});

app.get('/find', async (req, res) => {
  const name = req.query.name;
  // ruleid: sast.js.nosql-injection
  const list = await User.find({ name: name });
  res.json(list);
});

app.post('/upd', async (req, res) => {
  // ruleid: sast.js.nosql-injection
  await User.updateOne({ token: req.body.token }, { $set: { used: true } });
  // ruleid: sast.js.nosql-injection
  await User.deleteOne(req.body);
  res.end();
});

app.get('/where', async (req, res) => {
  // ruleid: sast.js.nosql-injection
  const r = await User.find({ $where: 'this.name == "' + req.query.name + '"' });
  res.json(r);
});

app.post('/safe', async (req, res) => {
  // ok: sast.js.nosql-injection
  const a = await User.findOne({ email: String(req.body.email) });
  // ok: sast.js.nosql-injection
  const b = await User.findOne({ email: `${req.body.email}` });
  // ok: sast.js.nosql-injection
  const c = await User.findOne({ age: Number(req.body.age) });
  // ok: sast.js.nosql-injection
  const d = await User.findOne({ email: mongoSanitize(req.body.email) });
  // ok: sast.js.nosql-injection
  const e = await User.findOne({ email: { $eq: req.body.email } });
  // ok: sast.js.nosql-injection
  const f = await User.findOne({ role: 'admin' });
  // ok: sast.js.nosql-injection
  const g = [1, 2, 3].find((x) => x === req.body.n);
  res.json([a, b, c, d, e, f, g]);
});
