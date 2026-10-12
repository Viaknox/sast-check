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
  res.end(t);
});
