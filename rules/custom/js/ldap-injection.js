// How this fixture is ordered (read before editing):
// The rule decides what a name means from the require/import that comes BEFORE it in the file. A binding only
// covers the code below it, and a require is stronger than an import (it also covers ES-import usage). So each
// binding form is tested in its own region, weakest binding first, so no earlier binding can stand in for it.
const express = require('express');
const app = express();
const ActiveDirectory = require('activedirectory');
const ad = new ActiveDirectory({});

// ---- look-alikes that are not LDAP clients, above every ldapjs/ldapts binding (#6 item 30) ----
app.get('/lookalikes', (req, res) => {
  const cache = makeCache();
  const dotted = cache.createClient({});
  // ok: sast.js.ldap-injection
  dotted.search('x', { filter: req.query.q }, () => {});
  const createClient = makeThing;
  const bare = createClient({});
  // ok: sast.js.ldap-injection
  bare.search('x', { filter: req.query.q }, () => {});
  const Client = FakeClient;
  const made = new Client({});
  // ok: sast.js.ldap-injection
  made.search('x', { filter: req.query.q }, () => {});
  const viaNs = new cache.Client({});
  // ok: sast.js.ldap-injection
  viaNs.search('x', { filter: req.query.q }, () => {});
  res.end();
});

// ---- search receivers: ldapjs, no module binding yet (#6 item 30) ----
app.get('/chain', (req, res) => {
  const viaChain = require('ldapjs').createClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  viaChain.search('dc=ex', { filter: '(uid=' + req.query.u + ')' }, () => {});
  res.end();
});

app.get('/ldapjs-cjs-plain', (req, res) => {
  const { createClient } = require('ldapjs');
  const plain = createClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  plain.search('dc=ex', { filter: '(uid=' + req.query.u + ')' }, () => {});
  res.end();
});

app.get('/ldapjs-cjs-alias', (req, res) => {
  const { createClient: build } = require('ldapjs');
  const viaBuild = build({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  viaBuild.search('dc=ex', { filter: '(uid=' + req.query.u + ')' }, () => {});
  res.end();
});

import { createClient } from 'ldapjs';
app.get('/ldapjs-esm-plain', (req, res) => {
  const viaNamed = createClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  viaNamed.search('dc=ex', { filter: '(uid=' + req.query.u + ')' }, () => {});
  res.end();
});

import { createClient as makeClient } from 'ldapjs';
app.get('/ldapjs-esm-alias', (req, res) => {
  const viaAlias = makeClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  viaAlias.search('dc=ex', { filter: '(uid=' + req.query.u + ')' }, () => {});
  res.end();
});

import * as ldapNs from 'ldapjs';
app.get('/ldapjs-esm-ns', (req, res) => {
  const viaNs = ldapNs.createClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  viaNs.search('dc=ex', { filter: '(uid=' + req.query.u + ')' }, () => {});
  res.end();
});

import ldapDefault from 'ldapjs';
app.get('/ldapjs-esm-default', (req, res) => {
  const viaDefault = ldapDefault.createClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  viaDefault.search('dc=ex', { filter: '(uid=' + req.query.u + ')' }, () => {});
  res.end();
});

// ---- search receivers: ldapts ----
app.get('/ldapts-cjs-plain', async (req, res) => {
  const { Client } = require('ldapts');
  const a = new Client({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  await a.search('dc=ex', { filter: '(uid=' + req.query.u + ')' });
  res.end();
});

app.get('/ldapts-cjs-alias', async (req, res) => {
  const { Client: CjsClient } = require('ldapts');
  const d = new CjsClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  await d.search('dc=ex', { filter: '(uid=' + req.query.u + ')' });
  res.end();
});

import { Client } from 'ldapts';
app.get('/ldapts-esm-plain', async (req, res) => {
  const f = new Client({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  await f.search('dc=ex', { filter: '(uid=' + req.query.u + ')' });
  res.end();
});

import { Client as TsClient } from 'ldapts';
app.get('/ldapts-esm-alias', async (req, res) => {
  const g = new TsClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  await g.search('dc=ex', { filter: '(uid=' + req.query.u + ')' });
  res.end();
});

import * as ldaptsNs from 'ldapts';
app.get('/ldapts-esm-ns', async (req, res) => {
  const h = new ldaptsNs.Client({ url: 'ldap://a' });
  const opts = { filter: `(uid=${req.query.u})` };
  // ruleid: sast.js.ldap-injection
  await h.search('dc=ex', opts);
  res.end();
});

const lt = require('ldapts');
app.get('/ldapts-cjs-ns', async (req, res) => {
  const e = new lt.Client({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-injection
  await e.search('dc=ex', { filter: '(uid=' + req.query.u + ')' });
  res.end();
});

// ---- the classic client, built from a top-level require ----
const ldap = require('ldapjs');
const client = ldap.createClient({ url: 'ldap://localhost' });

// ---- search receiver must be a real LDAP client (#6 item 30) ----
const api = new SearchApi();
const catalog = makeCatalog();

app.get('/not-ldap', (req, res) => {
  // ok: sast.js.ldap-injection
  api.search('products', { filter: req.query.q }, () => {});
  // ok: sast.js.ldap-injection
  catalog.search(req.query.q, () => {});
  const opts = { filter: req.query.q };
  // ok: sast.js.ldap-injection
  api.search('products', opts, () => {});
  res.end();
});

app.get('/multiline', (req, res) => {
  const opts = { filter: '(uid=' + req.query.u + ')' };
  client.search(
    'dc=ex',
    // ruleid: sast.js.ldap-injection
    opts,
    () => {}
  );
  res.end();
});

// ---- sanitizers: each binding form of the ldap-escape package, weakest binding first (#6 item 1) ----
app.get('/esc-lookalikes', (req, res) => {
  const filter = (v) => v;
  // ruleid: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: filter`(uid=${req.query.uid})` }, () => {});
  const fakeEsc = makeEscaper();
  // ruleid: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: fakeEsc.filter`(uid=${req.query.uid})` }, () => {});
  const clean = (v) => v;
  // ruleid: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: clean`(uid=${req.query.uid})` }, () => {});
  res.end();
});

app.get('/esc-cjs-plain', async (req, res) => {
  const { filter } = require('ldap-escape');
  // ok: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: filter`(uid=${req.query.uid})` }, () => {});
  res.end();
});

app.get('/esc-cjs-alias', async (req, res) => {
  const { filter: cjsFilter } = require('ldap-escape');
  // ok: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: cjsFilter`(uid=${req.query.uid})` }, () => {});
  res.end();
});

import { filter } from 'ldap-escape';
app.get('/esc-esm-plain', async (req, res) => {
  // ok: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: filter`(uid=${req.query.uid})` }, () => {});
  res.end();
});

import { filter as filterAliased } from 'ldap-escape';
app.get('/esc-esm-alias', async (req, res) => {
  // ok: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: filterAliased`(uid=${req.query.uid})` }, () => {});
  res.end();
});

import * as escNs from 'ldap-escape';
app.get('/esc-esm-ns', async (req, res) => {
  // ok: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: escNs.filter`(uid=${req.query.uid})` }, () => {});
  res.end();
});

import escDefault from 'ldap-escape';
app.get('/esc-esm-default', async (req, res) => {
  // ok: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: escDefault.filter`(uid=${req.query.uid})` }, () => {});
  res.end();
});

// ---- things that are NOT the package, above the require of it ----
app.get('/fake-obj', (req, res) => {
  // a local object that happens to be called ldapEscape is not the package
  const ldapEscape = { filter: (x) => x };
  // ruleid: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: ldapEscape.filter`(uid=${req.query.uid})` }, () => {});
  res.end();
});

function escapeFilter(v) { return v; }
function escapeLdapFilter(v) { return v; }

app.get('/fake-fn', (req, res) => {
  // ruleid: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: '(uid=' + escapeFilter(req.query.uid) + ')' }, () => {});
  // ruleid: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: '(uid=' + escapeLdapFilter(req.query.uid) + ')' }, () => {});
  res.end();
});

const ldapEscape = require('ldap-escape');

app.get('/user', (req, res) => {
  // ruleid: sast.js.ldap-injection
  client.search('ou=people,dc=ex,dc=com', { filter: '(uid=' + req.query.uid + ')', scope: 'sub' }, () => {});
  res.end();
});

app.post('/login', (req, res) => {
  const user = req.body.username;
  const opts = { filter: `(&(uid=${user})(objectClass=person))`, scope: 'sub' };
  // ruleid: sast.js.ldap-injection
  client.search('dc=ex,dc=com', opts, () => {});
  res.end();
});

app.get('/ad', (req, res) => {
  // ruleid: sast.js.ldap-injection
  ad.findUser(req.query.name, () => {});
  // ruleid: sast.js.ldap-injection
  ad.find('cn=' + req.params.cn, () => {});
  res.end();
});

app.get('/ad-more', (req, res) => {
  // ok: sast.js.ldap-injection
  ad.authenticate(req.body.user, req.body.pw, () => {});
  ad.findUser(
    // ruleid: sast.js.ldap-injection
    req.query.name,
    () => {}
  );
  res.end();
});

app.get('/safe', (req, res) => {
  // ok: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: ldapEscape.filter`(uid=${req.query.uid})`, scope: 'sub' }, () => {});
  // ok: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: '(uid=' + ldapEscape.filter(req.query.uid) + ')' }, () => {});
  // ok: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: '(objectClass=person)', scope: 'sub' }, () => {});
  // ruleid: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: '(uid=' + ldapEscape.dn(req.query.uid) + ')' }, () => {});
  // ok: sast.js.ldap-injection
  ad.findUser('jdoe', () => {});
  // ok: sast.js.ldap-injection
  const hits = [1, 2].find((n) => n === Number(req.query.n));
  res.end();
});

app.get('/mixed', (req, res) => {
  // ruleid: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: '(&(uid=' + ldapEscape.filter(req.query.uid) + ')(cn=' + req.query.cn + '))' }, () => {});
  res.end();
});

app.get('/shadowed', (req, res) => {
  // inside this handler ldapEscape is a local object again, even though the package is required above
  const ldapEscape = { filter: (x) => x };
  // ruleid: sast.js.ldap-injection
  client.search('dc=ex,dc=com', { filter: ldapEscape.filter`(uid=${req.query.uid})` }, () => {});
  res.end();
});
