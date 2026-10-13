const vm = require('vm');
const express = require('express');
const app = express();

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
