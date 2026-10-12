const express = require('express');
const app = express();

app.get('/page', (req, res) => {
  // ruleid: sast.js.express-render-ssti
  res.render(req.query.page);
});

app.get('/tpl/:name', (req, res) => {
  // ruleid: sast.js.express-render-ssti
  res.render(`pages/${req.params.name}`, { title: 'x' });
});

app.get('/opts', (req, res) => {
  // ruleid: sast.js.express-render-ssti
  res.render('profile', req.query);
});

app.post('/opts2', (req, res) => {
  // ruleid: sast.js.express-render-ssti
  res.render('profile', req.body);
});

app.get('/safe', (req, res) => {
  // ok: sast.js.express-render-ssti
  res.render('home');
  // ok: sast.js.express-render-ssti
  res.render('profile', { name: req.query.name });
  // ok: sast.js.express-render-ssti
  res.render('profile', { user: req.body.user, flag: true });
  // ok: sast.js.express-render-ssti
  res.render('pages/' + path.basename(req.query.page));
  // ok: sast.js.express-render-ssti
  const view = 'detail';
  res.render(view, { id: req.params.id });
});
