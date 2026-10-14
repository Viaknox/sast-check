// How this fixture is ordered (read before editing):
// The rule decides what a vm name means from the require/import that comes BEFORE it in the file, and a
// require is stronger than an import (it also covers ES-import usage). So each binding form is tested in its
// own region, weakest binding first, so no earlier binding can stand in for it.
const express = require('express');
const app = express();

// ---- vm look-alikes: nothing here comes from the vm module (#6 item 11) ----
const other = makeThing();

app.post('/not-vm', (req, res) => {
  // a variable that is merely called vm, and an object with the same method names
  const vm = makeSandbox();
  // ok: sast.js.code-eval
  vm.runInNewContext(req.body.script, {});
  // ok: sast.js.code-eval
  other.runInThisContext(req.body.script);
  // ok: sast.js.code-eval
  new vm.Script(req.body.script);
  // ok: sast.js.code-eval
  new other.Script(req.body.script);
  // ok: sast.js.code-eval
  runInNewContext(req.body.script);
  // ok: sast.js.code-eval
  new Script(req.body.script);
  res.end();
});

// ---- named imports of vm ----
app.post('/vm-cjs-script', (req, res) => {
  const { Script } = require('node:vm');
  // ruleid: sast.js.code-eval
  new Script(req.body.script).runInThisContext();
  res.end();
});

import { runInThisContext } from 'node:vm';
app.post('/vm-named-node', (req, res) => {
  // ruleid: sast.js.code-eval
  runInThisContext(req.body.script);
  res.end();
});

import { runInNewContext } from 'vm';
app.post('/vm-named', (req, res) => {
  // ruleid: sast.js.code-eval
  runInNewContext(req.body.script, {});
  res.end();
});

import { Script } from 'vm';
import { createContext } from 'vm';
app.post('/vm-named-script', (req, res) => {
  // ruleid: sast.js.code-eval
  new Script(req.body.script);
  // ok: sast.js.code-eval
  createContext(req.body.sandbox);
  res.end();
});

// ---- named imports of vm under another name ----
import { runInContext as runIn } from 'node:vm';
import { Script as VmScript } from 'vm';
import { createContext as makeCtx } from 'vm';
app.post('/vm-aliased', (req, res) => {
  // ruleid: sast.js.code-eval
  runIn(req.body.script, ctx);
  // ruleid: sast.js.code-eval
  new VmScript(req.body.script);
  // ok: sast.js.code-eval
  makeCtx(req.body.sandbox);
  res.end();
});

// ---- vm functions taken straight off a require (item 3, PR #11 review 4) ----
const evalInSandbox = require('vm').runInNewContext;
const evalNode = require('node:vm').runInThisContext;
const run = require('vm').runInThisContext;
const VmScriptCjs = require('node:vm').Script;
const buildCtx = require('vm').createContext;
const otherRun = require('some-sandbox').runInNewContext;
const OtherScript = require('some-sandbox').Script;
app.post('/vm-require-property', (req, res) => {
  // ruleid: sast.js.code-eval
  evalInSandbox(req.body.code, {});
  // ruleid: sast.js.code-eval
  evalNode(req.body.code);
  // ruleid: sast.js.code-eval
  run(req.body.code);
  // ruleid: sast.js.code-eval
  new VmScriptCjs(req.body.code);
  // not an evaluator
  // ok: sast.js.code-eval
  buildCtx(req.body.sandbox);
  // the same property taken from another module
  // ok: sast.js.code-eval
  otherRun(req.body.code);
  // ok: sast.js.code-eval
  new OtherScript(req.body.code);
  // fixed text
  // ok: sast.js.code-eval
  run('1 + 1');
  // only the code argument is a sink, not the sandbox
  // ok: sast.js.code-eval
  run('1 + 1', req.body.sandbox);
  res.end();
});

// ---- namespace and default imports of vm ----
import * as vmNodeNs from 'node:vm';
app.post('/vm-ns-node', (req, res) => {
  // ruleid: sast.js.code-eval
  vmNodeNs.runInNewContext(req.body.script, {});
  res.end();
});

import * as vmNs from 'vm';
app.post('/vm-ns', (req, res) => {
  // ruleid: sast.js.code-eval
  vmNs.runInContext(req.body.script, ctx);
  // ruleid: sast.js.code-eval
  new vmNs.Script(req.body.script);
  res.end();
});

import vmDefaultNode from 'node:vm';
app.post('/vm-default-node', (req, res) => {
  // ruleid: sast.js.code-eval
  vmDefaultNode.runInThisContext(req.body.script);
  res.end();
});

import vmDefault from 'vm';
app.post('/vm-default', (req, res) => {
  // ruleid: sast.js.code-eval
  vmDefault.compileFunction(req.body.script);
  res.end();
});

// ---- the classic require ----
const nodeVm = require('node:vm');
const sandboxLib = require('vm2');
app.post('/not-core-vm', (req, res) => {
  // ok: sast.js.code-eval
  sandboxLib.runInNewContext(req.body.script, {});
  res.end();
});
const vm = require('vm');

app.post('/vm-required', (req, res) => {
  // ruleid: sast.js.code-eval
  nodeVm.runInNewContext(req.body.script, {});
  // ruleid: sast.js.code-eval
  vm.runInThisContext(req.body.script);
  // ok: sast.js.code-eval
  vm.createContext(req.body.sandbox);
  // ok: sast.js.code-eval
  vm.runInNewContext('1 + 1', req.body.sandbox);
  res.end();
});

app.post('/multiline', (req, res) => {
  vm.runInNewContext(
    // ruleid: sast.js.code-eval
    req.body.script,
    {}
  );
  new vm.Script(
    // ruleid: sast.js.code-eval
    req.body.script
  );
  setTimeout(
    // ruleid: sast.js.code-eval
    req.body.cb,
    10
  );
  runInNewContext(
    // ruleid: sast.js.code-eval
    req.body.script
  );
  new Script(
    // ruleid: sast.js.code-eval
    req.body.script
  );
  res.end();
});

// ---- handlers registered by name, defined elsewhere in the file (#6 item 11b) ----
function execute(r, res) {
  // ruleid: sast.js.code-eval
  res.send(String(eval(r.query.code)));
}
app.post('/named', execute);

app.get('/named-later', runLater);
function runLater(q, res) {
  // ruleid: sast.js.code-eval
  res.send(String(eval(q.body.code)));
}

async function runAsync(q, res) {
  // ruleid: sast.js.code-eval
  res.send(String(eval(q.params.code)));
}
app.use(runAsync);

const runArrow = (a, res) => {
  // ruleid: sast.js.code-eval
  res.send(String(eval(a.query.code)));
};
router.put('/arrow', checkAuth, runArrow);

const runArrowAsync = async (a, res) => {
  // ruleid: sast.js.code-eval
  res.send(String(eval(a.body.code)));
};
userRouter.patch('/arrow-async', runArrowAsync);

const runExpr = function (a, res) {
  // ruleid: sast.js.code-eval
  res.send(String(eval(a.query.code)));
};
router.delete('/expr', runExpr);

// every request property counts for a named handler, same as for an inline one
function readEverything(r, res) {
  // ruleid: sast.js.code-eval
  eval(r.params.a);
  // ruleid: sast.js.code-eval
  eval(r.headers.a);
  // ruleid: sast.js.code-eval
  eval(r.cookies.a);
  // ruleid: sast.js.code-eval
  eval(r.url);
  // ruleid: sast.js.code-eval
  eval(r.originalUrl);
  // ruleid: sast.js.code-eval
  eval(r.path);
  // ruleid: sast.js.code-eval
  eval(r.get('x-code'));
  // ruleid: sast.js.code-eval
  eval(r.header('x-code'));
  // ok: sast.js.code-eval
  eval('1 + 1');
  // ok: sast.js.code-eval
  eval(r.method);
}
app.all('/everything', readEverything);

// registered, but not as a route handler (param callbacks and settings take other arguments)
function paramHook(r, res) {
  // ok: sast.js.code-eval
  res.send(String(eval(r.query.code)));
}
app.param('id', paramHook);

// not registered on a route: the first parameter is just a parameter
function notAHandler(r, res) {
  // ok: sast.js.code-eval
  res.send(String(eval(r.query.code)));
}
cache.set('k', notAHandler);

function neverRegistered(r, res) {
  // ok: sast.js.code-eval
  res.send(String(eval(r.query.code)));
}

function registeredElsewhere(r, res) {
  // ok: sast.js.code-eval
  res.send(String(eval(r.body.code)));
}
emitter.get('k', registeredElsewhere);

// ---- original cases ----
app.get('/calc', (req, res) => {
  // ruleid: sast.js.code-eval
  const r = eval(req.query.expr);
  res.send(String(r));
});

app.post('/fn', (req, res) => {
  const body = req.body.code;
  // ruleid: sast.js.code-eval
  const f = new Function('a', body);
  res.json(f(1));
});

app.post('/vm', (req, res) => {
  // ruleid: sast.js.code-eval
  res.json(vm.runInNewContext(req.body.script, {}));
});

app.get('/vm2', (req, res) => {
  const src = req.query.src;
  // ruleid: sast.js.code-eval
  const script = new vm.Script(src);
  res.json(script.runInThisContext());
});

app.get('/timer', (req, res) => {
  // ruleid: sast.js.code-eval
  setTimeout(req.query.cb, 10);
  // ruleid: sast.js.code-eval
  setInterval('tick(' + req.query.n + ')', 1000);
  res.end();
});

app.post('/json-eval', (req, res) => {
  // ruleid: sast.js.code-eval
  const v = eval(JSON.parse(req.body.x));
  res.json(v);
});

app.get('/safe', (req, res) => {
  // ok: sast.js.code-eval
  setTimeout(() => console.log(req.query.x), 10);
  // ok: sast.js.code-eval
  setTimeout(function () { work(req.query.id); }, 100);
  // ok: sast.js.code-eval
  setTimeout(done, Number(req.query.delay));
  // ok: sast.js.code-eval
  const data = JSON.parse(req.body.payload);
  // ok: sast.js.code-eval
  const total = eval('1 + 1');
  // ok: sast.js.code-eval
  const add = new Function('a', 'b', 'return a + b');
  // ok: sast.js.code-eval
  const out = vm.runInNewContext('2 * 21', {});
  // ok: sast.js.code-eval
  setTimeout('tick()', 1000);
  res.json({ data, total, add: add(1, 2), out });
});

app.post('/alias', (r, res) => {
  // ruleid: sast.js.code-eval
  res.send(String(eval(r.query.code)));
});

router.get('/alias2', async function (rq, rs) {
  // ruleid: sast.js.code-eval
  new Function(rq.body.src)();
  // ok: sast.js.code-eval
  rs.send(String(eval('6 * 7')));
});

app.get('/eval-header', (req, res) => {
  // ruleid: sast.js.code-eval
  eval(req.get('x-code'));
  res.end();
});

// expression-bodied handlers with a renamed request parameter
// ruleid: sast.js.code-eval
app.get('/expr', (r, res) => res.send(String(eval(r.query.code))));
// ruleid: sast.js.code-eval
app.post('/expr-async', async (r, res) => res.json(new Function(r.body.src)()));
// ok: sast.js.code-eval
app.get('/expr-ok', (r, res) => res.send(String(eval('6 * 7'))));
