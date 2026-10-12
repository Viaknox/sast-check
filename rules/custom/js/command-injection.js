const { exec, execSync, spawn, execFile } = require('child_process');
const cp = require('child_process');
const express = require('express');
const app = express();

app.get('/ping', (req, res) => {
  // ruleid: sast.js.command-injection
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

app.get('/lookup', (req, res) => {
  const name = req.params.name;
  // ruleid: sast.js.command-injection
  const out = execSync(`nslookup ${name}`);
  res.send(out);
});

app.get('/ls', (req, res) => {
  // ruleid: sast.js.command-injection
  cp.exec(req.body.cmd, () => res.end());
});

app.get('/sp', (req, res) => {
  // ruleid: sast.js.command-injection
  spawn('git', ['log', req.query.ref], { shell: true });
  // ruleid: sast.js.command-injection
  spawn(req.query.program, ['--version']);
  // ruleid: sast.js.command-injection
  spawn('sh', ['-c', req.body.script]);
  res.end();
});

app.get('/safe', (req, res) => {
  // ok: sast.js.command-injection
  execFile('git', ['log', req.query.ref], (e, o) => res.send(o));
  // ok: sast.js.command-injection
  spawn('ls', ['-l', req.query.dir]);
  // ok: sast.js.command-injection
  exec('uptime', (e, o) => res.send(o));
  // ok: sast.js.command-injection
  exec('sleep ' + Number(req.query.secs));
  // ruleid: sast.js.command-injection
  exec('echo ' + JSON.stringify(req.query.msg));
  // ok: sast.js.command-injection
  const m = /a(b)/.exec(req.query.text);
  // ok: sast.js.command-injection
  spawn('ls', ['-l', req.query.dir], { shell: false });
  res.json(m);
});

app.get('/ls-path', (req, res) => {
  // ruleid: sast.js.command-injection
  exec('ls ' + req.path);
  res.end();
});

app.get('/quote', (req, res) => {
  // ruleid: sast.js.command-injection
  exec('ls ' + formatter.quote(req.query.cmd));
  // ok: sast.js.command-injection
  exec('ls ' + shellQuote.quote([req.query.cmd]));
  // ok: sast.js.command-injection
  exec('ls ' + shq.quote(req.query.dir));
  res.end();
});
