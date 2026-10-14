// How this fixture is ordered (read before editing):
// The rule decides what exec/spawn mean from the require/import that comes BEFORE it in the file, and a
// require is stronger than an import (it also covers ES-import usage). So each binding form is tested in its
// own region, weakest binding first, so no earlier binding can stand in for it.
const express = require('express');
const app = express();

// ---- look-alikes: nothing here comes from child_process (#6 item 29) ----
app.get('/not-child-process', (req, res) => {
  // ok: sast.js.command-injection
  db.exec('select * from t where id = ' + req.query.id);
  // ok: sast.js.command-injection
  proc.exec(req.query.cmd);
  // ok: sast.js.command-injection
  child_process_lookalike.execSync(req.body.cmd);
  // ok: sast.js.command-injection
  exec(req.query.cmd);
  // ok: sast.js.command-injection
  spawn(req.query.cmd, []);
  // ok: sast.js.command-injection
  spawn('git', ['log', req.query.ref], { shell: true });
  // ok: sast.js.command-injection
  spawn('sh', ['-c', req.body.script]);
  res.end();
});

// ---- a function taken off the module and bound to any name ----
app.get('/extract-exec', (req, res) => {
  const exec = require('child_process').exec;
  // ruleid: sast.js.command-injection
  exec(req.query.cmd);
  res.end();
});
app.get('/extract-node', (req, res) => {
  const run = require('node:child_process').execSync;
  // ruleid: sast.js.command-injection
  run('ls ' + req.query.dir);
  res.end();
});
app.get('/extract-alias', (req, res) => {
  const run = require('child_process').execSync;
  // ruleid: sast.js.command-injection
  run(req.query.cmd);
  res.end();
});
app.get('/extract-spawn', (req, res) => {
  const launch = require('child_process').spawn;
  // ruleid: sast.js.command-injection
  launch('git', ['log', req.query.ref], { shell: true });
  // ruleid: sast.js.command-injection
  launch('sh', ['-c', req.body.script]);
  // ok: sast.js.command-injection
  launch('git', ['log', req.query.ref]);
  // ok: sast.js.command-injection
  launch('python3', ['-c', req.body.script]);
  res.end();
});
app.get('/extract-other', (req, res) => {
  const exec = require('lodash').exec;
  // ok: sast.js.command-injection
  exec(req.query.cmd);
  const fork = require('child_process').fork;
  // ok: sast.js.command-injection
  fork(req.query.module);
  const sh = require('shelljs').exec;
  // ok: sast.js.command-injection
  sh(req.query.cmd);
  res.end();
});

// ---- named imports ----
import { execSync } from 'node:child_process';
app.get('/named-node', (req, res) => {
  // ruleid: sast.js.command-injection
  execSync(`ls ${req.query.dir}`);
  res.end();
});

import { spawnSync, fork } from 'child_process';
app.get('/named', (req, res) => {
  // ruleid: sast.js.command-injection
  spawnSync(req.query.program, ['--version']);
  // ruleid: sast.js.command-injection
  spawnSync('git', ['log', req.query.ref], { shell: true });
  // ruleid: sast.js.command-injection
  spawnSync('sh', ['-c', req.body.script]);
  // ok: sast.js.command-injection
  spawnSync('git', ['log', req.query.ref]);
  // ok: sast.js.command-injection
  spawnSync('python3', ['-c', req.body.script]);
  // ok: sast.js.command-injection
  fork(req.query.module);
  // fork runs a script with node, not a shell: the shell option and -c mean nothing to it
  // ok: sast.js.command-injection
  fork('worker.js', [req.query.arg], { shell: true });
  // ok: sast.js.command-injection
  fork('sh', ['-c', req.body.script]);
  res.end();
});

// ---- named imports under another name ----
import { exec as runCmd } from 'node:child_process';
import { spawn as launch } from 'child_process';
import { fork as forkIt } from 'child_process';
app.get('/aliased', (req, res) => {
  // ruleid: sast.js.command-injection
  runCmd('ls ' + req.query.dir);
  // ruleid: sast.js.command-injection
  launch('git', ['log', req.query.ref], { shell: true });
  // ruleid: sast.js.command-injection
  launch('sh', ['-c', req.body.script]);
  // ok: sast.js.command-injection
  launch('git', ['log', req.query.ref]);
  // ok: sast.js.command-injection
  launch('python3', ['-c', req.body.script]);
  // ok: sast.js.command-injection
  forkIt(req.query.module);
  // ok: sast.js.command-injection
  forkIt('worker.js', [req.query.arg], { shell: true });
  // ok: sast.js.command-injection
  forkIt('sh', ['-c', req.body.script]);
  res.end();
});

app.get('/aliased-require', (req, res) => {
  const { execFile: runFile } = require('child_process');
  // ruleid: sast.js.command-injection
  runFile(req.query.bin);
  res.end();
});

// ---- namespace and default imports ----
import * as cpNodeNs from 'node:child_process';
app.get('/ns-node', (req, res) => {
  // ruleid: sast.js.command-injection
  cpNodeNs.exec('ping ' + req.query.host);
  res.end();
});

import * as cpNs from 'child_process';
app.get('/ns', (req, res) => {
  // ruleid: sast.js.command-injection
  cpNs.execFileSync(req.query.bin);
  res.end();
});

import cpDefaultNode from 'node:child_process';
app.get('/default-node', (req, res) => {
  // ruleid: sast.js.command-injection
  cpDefaultNode.spawn('git', ['log', req.query.ref], { shell: true });
  res.end();
});

import cpDefault from 'child_process';
app.get('/default', (req, res) => {
  // ruleid: sast.js.command-injection
  cpDefault.spawnSync('sh', ['-c', req.body.script]);
  res.end();
});

// ---- the classic require ----
const { exec, spawn, execFile } = require('child_process');
const cp = require('child_process');
const cpNode = require('node:child_process');
const shelljs = require('shelljs');

app.get('/required', (req, res) => {
  // ruleid: sast.js.command-injection
  cpNode.exec('whoami ' + req.query.user);
  // ruleid: sast.js.command-injection
  cp.spawn('sh', ['-c', req.body.script]);
  // ruleid: sast.js.command-injection
  cp.execFile('git', ['log', req.query.ref], { shell: true });
  // ok: sast.js.command-injection
  cp.execFile('git', ['log', req.query.ref]);
  // ok: sast.js.command-injection
  cp.spawn('python3', ['-c', req.body.script]);
  // ok: sast.js.command-injection
  cp.fork(req.query.module);
  // ok: sast.js.command-injection
  cp.fork('worker.js', [req.query.arg], { shell: true });
  // ok: sast.js.command-injection
  cp.fork('sh', ['-c', req.body.script]);
  // ok: sast.js.command-injection
  shelljs.exec('ls ' + req.query.dir);
  res.end();
});

app.get('/multiline', (req, res) => {
  cp.exec(
    // ruleid: sast.js.command-injection
    req.query.cmd,
    () => {}
  );
  exec(
    // ruleid: sast.js.command-injection
    req.query.cmd,
    () => {}
  );
  res.end();
});

// ---- original cases ----
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

// expression-bodied handler with a renamed request parameter
// ruleid: sast.js.command-injection
app.get('/expr', (r, res) => res.send(execSync('ping ' + r.query.host)));
