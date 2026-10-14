// How this fixture is ordered (read before editing):
// A page handed in as a parameter only counts once puppeteer is imported earlier in the file, so the
// no-import look-alikes come first, then one region per way of importing, then the main fixture.

// ---- no puppeteer import above this point: a parameter's name proves nothing ----
async function noLibGoto(page, req) {
  // ok: sast.js.puppeteer-ssrf
  await page.goto(req.query.url);
}

async function noLibContent(page, req) {
  // ok: sast.js.puppeteer-ssrf
  page.setContent(req.body.html);
  // ok: sast.js.puppeteer-ssrf
  page.addScriptTag({ url: req.query.src });
}

// ---- puppeteer-core required inside the function that receives the page ----
async function viaCoreRequire(page, req) {
  const core = require('puppeteer-core');
  // ruleid: sast.js.puppeteer-ssrf
  await page.goto(req.query.url);
  // ruleid: sast.js.puppeteer-ssrf
  await page.setContent(req.body.html);
}
// ---- modules that are not puppeteer (required inside the function, then imported) ----
async function otherRequire(page, req) {
  const lodash = require('lodash');
  // ok: sast.js.puppeteer-ssrf
  await page.goto(req.query.url);
  // ok: sast.js.puppeteer-ssrf
  await page.setContent(req.body.html);
  // ok: sast.js.puppeteer-ssrf
  await page.addScriptTag({ url: req.query.src });
}

import otherLib from 'lodash';
async function afterOtherImport(page, req) {
  // ok: sast.js.puppeteer-ssrf
  await page.goto(req.query.url);
  // ok: sast.js.puppeteer-ssrf
  await page.setContent(req.body.html);
  // ok: sast.js.puppeteer-ssrf
  await page.addScriptTag({ url: req.query.src });
}

// ---- each way of importing puppeteer, in its own region (an import covers everything below it) ----
// `import * as` is first because only it is tested alone; a default import is read by the `import { }` pattern
import * as ppStar from 'puppeteer-core';
async function afterStarImport(page, req) {
  // ruleid: sast.js.puppeteer-ssrf
  await page.goto(req.query.url);
  // ruleid: sast.js.puppeteer-ssrf
  await page.evaluate(req.body.script);
}

import puppeteerDefault from 'puppeteer';
async function afterDefaultImport(page, req) {
  // ruleid: sast.js.puppeteer-ssrf
  await page.goto(req.query.url);
  // ruleid: sast.js.puppeteer-ssrf
  await page.setContent(req.body.html);
}

// the reviewer's shape: a default import and a helper that takes the page (PR #11 review 3). Checked ALONE in a
// scratch copy (default import first, no other puppeteer binding above) on opengrep 1.30.2 and semgrep: it matched,
// so `import { ... } from $M` does read default imports. It sits here because an import covers the rest of the file.
function visit(page, req) {
  // ruleid: sast.js.puppeteer-ssrf
  return page.goto(req.query.url);
}

import { launch } from 'puppeteer';
async function afterNamedImport(page, req) {
  // ruleid: sast.js.puppeteer-ssrf
  await page.goto(req.query.url);
  // ruleid: sast.js.puppeteer-ssrf
  await page.addScriptTag({ content: req.body.code });
}


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

// ---- the page is a parameter of the function (puppeteer is required at the top of this file) ----
async function shoot(page, req) {
  // ruleid: sast.js.puppeteer-ssrf
  await page.goto(req.query.url);
}

const render = async (pg, req) => {
  // ruleid: sast.js.puppeteer-ssrf
  await pg.setContent(req.body.html);
  // ruleid: sast.js.puppeteer-ssrf
  await pg.evaluate(req.body.script);
  // ruleid: sast.js.puppeteer-ssrf
  await pg.addScriptTag({ url: req.query.src });
};

function plain(p, req) {
  // ruleid: sast.js.puppeteer-ssrf
  return p.waitForFunction(req.body.expr);
}

async function safeParam(page, req) {
  // ok: sast.js.puppeteer-ssrf
  await page.goto('https://example.com/r?id=' + encodeURIComponent(req.query.id));
  // ok: sast.js.puppeteer-ssrf
  await page.setContent('<h1>Static</h1>');
  // ok: sast.js.puppeteer-ssrf
  await page.addScriptTag({ url: 'https://example.com/app.js' });
}

// a local that is not a parameter and not from newPage() is still not a page
function localNotParam(req) {
  const tab = makeTab();
  // ok: sast.js.puppeteer-ssrf
  return tab.goto(req.query.url);
}

// ---- inline newPage() receivers, same shapes as the variable form ----
app.get('/inline-all', async (req, res) => {
  const browser = await puppeteer.launch();
  // ruleid: sast.js.puppeteer-ssrf
  await (await browser.newPage()).addScriptTag({ url: req.query.src });
  // ruleid: sast.js.puppeteer-ssrf
  await (await browser.newPage()).addScriptTag({ content: req.body.code });
  // ok: sast.js.puppeteer-ssrf
  await (await browser.newPage()).addScriptTag({ url: 'https://example.com/app.js' });
  res.end();
});

// ---- other page methods and other script-tag keys are not sinks, on either receiver form ----
app.get('/other-methods', async (req, res) => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  // ok: sast.js.puppeteer-ssrf
  await page.click(req.query.sel);
  // ok: sast.js.puppeteer-ssrf
  await page.addScriptTag({ type: req.query.t });
  // ok: sast.js.puppeteer-ssrf
  await (await browser.newPage()).click(req.query.sel);
  // ok: sast.js.puppeteer-ssrf
  await (await browser.newPage()).addScriptTag({ type: req.query.t });
  res.end();
});

// ---- the finding sits on the request data, even when the call spans lines ----
app.get('/multi-line', async (req, res) => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto(
    // ruleid: sast.js.puppeteer-ssrf
    req.query.url);
  await page.setContent(
    // ruleid: sast.js.puppeteer-ssrf
    req.body.html);
  await page.addScriptTag({
    // ruleid: sast.js.puppeteer-ssrf
    url: req.query.src });
  await (await browser.newPage()).setContent(
    // ruleid: sast.js.puppeteer-ssrf
    req.body.html);
  await (await browser.newPage()).addScriptTag({
    // ruleid: sast.js.puppeteer-ssrf
    url: req.query.src });
  res.end();
});
