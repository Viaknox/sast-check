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

app.get('/where-cast', async (req, res) => {
  // a string cast does not stop JavaScript injection inside $where
  // ruleid: sast.js.nosql-injection
  const a = await User.find({ $where: 'this.name == "' + String(req.query.name) + '"' });
  // ruleid: sast.js.nosql-injection
  const b = await User.find({ $where: `this.name == "${req.query.name}"` });
  // ruleid: sast.js.nosql-injection
  const c = await User.find({ $where: 'this.name == "' + mongoSanitize(req.query.name) + '"' });
  // ok: sast.js.nosql-injection
  const d = await User.find({ $where: 'this.age == ' + Number(req.query.age) });
  res.json([a, b, c, d]);
});

app.post('/html-sanitize', async (req, res) => {
  // sanitize() is an HTML/no-op wrapper here, it does not strip Mongo operators
  // ruleid: sast.js.nosql-injection
  const h = await User.findOne({ email: sanitize(req.body.email) });
  // ruleid: sast.js.nosql-injection
  const k = await User.findOne({ email: xss.sanitize(req.body.email) });
  res.json([h, k]);
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
