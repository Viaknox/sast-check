const puppeteer = require('puppeteer');
const express = require('express');
const app = express();

app.get('/shot', async (req, res) => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  // ruleid: sast.js.puppeteer-ssrf
  await page.goto(req.query.url);
  res.end(await page.screenshot());
});

app.post('/pdf', async (req, res) => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  // ruleid: sast.js.puppeteer-ssrf
  await page.setContent(req.body.html);
  res.end(await page.pdf());
});

app.post('/eval', async (req, res) => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const code = req.body.script;
  // ruleid: sast.js.puppeteer-ssrf
  const out = await page.evaluate(code);
  res.json(out);
});

app.get('/inline', async (req, res) => {
  const browser = await puppeteer.launch();
  // ruleid: sast.js.puppeteer-ssrf
  await (await browser.newPage()).goto(`${req.params.target}`);
  res.end();
});

app.get('/safe', async (req, res) => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  // ok: sast.js.puppeteer-ssrf
  await page.goto('https://example.com/report');
  // ok: sast.js.puppeteer-ssrf
  await page.goto('https://example.com/report?id=' + encodeURIComponent(req.query.id));
  // ok: sast.js.puppeteer-ssrf
  await page.setContent('<h1>Static</h1>');
  // ok: sast.js.puppeteer-ssrf
  const t = await page.evaluate(() => document.title);
  // ok: sast.js.puppeteer-ssrf
  await page.evaluate((n) => window.scrollTo(0, n), Number(req.query.y));
  // ok: sast.js.puppeteer-ssrf
  await page.goto(process.env.REPORT_URL);
  // ruleid: sast.js.puppeteer-ssrf
  await page.evaluate(encodeURIComponent(req.query.code));
  // ok: sast.js.puppeteer-ssrf
  await page.goto(encodeURIComponent(req.query.slug));
  // ruleid: sast.js.puppeteer-ssrf
  await page.setContent('https://trusted.example/' + req.body.html);
  // ruleid: sast.js.puppeteer-ssrf
  await page.evaluate('https://trusted.example/' + req.body.code);
  const u = 'https://example.com/r/' + req.query.id;
  // ok: sast.js.puppeteer-ssrf
  await page.goto(u);
  res.end(t);
});

app.get('/host', async (req, res) => {
  const page = await (await puppeteer.launch()).newPage();
  // ruleid: sast.js.puppeteer-ssrf
  await page.goto('https://' + req.query.host + '/' + 'x');
  res.end();
});

// ---- the page is whatever newPage() returned, not a variable with a page-like name (#6 item 13) ----
app.get('/renamed', async (req, res) => {
  const browser = await puppeteer.launch();
  const p = await browser.newPage();
  // ruleid: sast.js.puppeteer-ssrf
  await p.goto(req.query.url);
  const renderer = await browser.newPage();
  // ruleid: sast.js.puppeteer-ssrf
  await renderer.setContent(req.body.html);
  let shot;
  shot = await browser.newPage();
  // ruleid: sast.js.puppeteer-ssrf
  await shot.evaluate(req.body.script);
  const viaContext = await browser.createBrowserContext();
  const q = await viaContext.newPage();
  // ruleid: sast.js.puppeteer-ssrf
  await q.goto(req.query.target);
  const r = await (await puppeteer.launch()).newPage();
  // ruleid: sast.js.puppeteer-ssrf
  await r.addScriptTag({ url: req.query.src });
  // ruleid: sast.js.puppeteer-ssrf
  await (await browser.newPage()).evaluate(req.body.script);
  res.end();
});

// ---- setContent / evaluate / goto on something that is not a page (#6 item 14) ----
app.get('/not-a-page', async (req, res) => {
  const tab = makeTab();
  const frame = getFrame();
  const cache = makeCache();
  const tpl = loadTemplate();
  // ok: sast.js.puppeteer-ssrf
  await tab.goto(req.query.url);
  // ok: sast.js.puppeteer-ssrf
  await frame.evaluate(req.body.script);
  // ok: sast.js.puppeteer-ssrf
  cache.evaluate(req.body.expr);
  // ok: sast.js.puppeteer-ssrf
  tpl.setContent(req.body.html);
  // ok: sast.js.puppeteer-ssrf
  tpl.addScriptTag({ url: req.query.src });
  const browser = await puppeteer.launch();
  // ok: sast.js.puppeteer-ssrf
  await browser.setContent(req.body.html);
  const page = await browser.newPage();
  const other = makeThing();
  // ok: sast.js.puppeteer-ssrf
  await other.goto(req.query.url);
  res.end();
});
