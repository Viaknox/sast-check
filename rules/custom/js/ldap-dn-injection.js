// How this fixture is ordered (read before editing):
// The rule decides what a name means from the require/import that comes BEFORE it in the file, and a require
// is stronger than an import (it also covers ES-import usage). So each binding form is tested in its own
// region, weakest binding first, so no earlier binding can stand in for it.
const express = require('express');
const app = express();

// ---- look-alikes that are not LDAP clients, above every ldapjs/ldapts binding (#6 receiver binding) ----
app.get('/lookalikes', (req, res) => {
  const cache = makeCache();
  const dotted = cache.createClient({});
  // ok: sast.js.ldap-dn-injection
  dotted.bind('uid=' + req.body.user, req.body.pw, () => {});
  const createClient = makeThing;
  const bare = createClient({});
  // ok: sast.js.ldap-dn-injection
  bare.del('uid=' + req.body.user, () => {});
  const Client = FakeClient;
  const made = new Client({});
  // ok: sast.js.ldap-dn-injection
  made.add('uid=' + req.body.user, {}, () => {});
  const viaNs = new cache.Client({});
  // ok: sast.js.ldap-dn-injection
  viaNs.search(req.query.base, {}, () => {});
  // the old name list trusted anything called client, ad, directory, conn
  const client = makeHttpThing();
  // ok: sast.js.ldap-dn-injection
  client.del('/items/' + req.params.id, () => {});
  const directory = loadDirectory();
  // ok: sast.js.ldap-dn-injection
  directory.add(req.body.entry, () => {});
  res.end();
});

// ---- ldapjs / ldapts clients, each binding form on its own ----
app.get('/chain', (req, res) => {
  const viaChain = require('ldapjs').createClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  viaChain.bind('uid=' + req.body.user, req.body.pw, () => {});
  res.end();
});

app.get('/ldapjs-cjs-plain', (req, res) => {
  const { createClient } = require('ldapjs');
  const plain = createClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  plain.bind('uid=' + req.body.user, req.body.pw, () => {});
  res.end();
});

app.get('/ldapjs-cjs-alias', (req, res) => {
  const { createClient: build } = require('ldapjs');
  const viaBuild = build({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  viaBuild.bind('uid=' + req.body.user, req.body.pw, () => {});
  res.end();
});

import { createClient } from 'ldapjs';
app.get('/ldapjs-esm-plain', (req, res) => {
  const viaNamed = createClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  viaNamed.bind('uid=' + req.body.user, req.body.pw, () => {});
  res.end();
});

import { createClient as makeClient } from 'ldapjs';
app.get('/ldapjs-esm-alias', (req, res) => {
  const viaAlias = makeClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  viaAlias.bind('uid=' + req.body.user, req.body.pw, () => {});
  res.end();
});

import * as ldapNs from 'ldapjs';
app.get('/ldapjs-esm-ns', (req, res) => {
  const viaNs = ldapNs.createClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  viaNs.bind('uid=' + req.body.user, req.body.pw, () => {});
  res.end();
});

import ldapDefault from 'ldapjs';
app.get('/ldapjs-esm-default', (req, res) => {
  const viaDefault = ldapDefault.createClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  viaDefault.bind('uid=' + req.body.user, req.body.pw, () => {});
  res.end();
});

app.get('/ldapts-cjs-plain', async (req, res) => {
  const { Client } = require('ldapts');
  const a = new Client({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  await a.bind('uid=' + req.body.user, req.body.pw);
  res.end();
});

app.get('/ldapts-cjs-alias', async (req, res) => {
  const { Client: CjsClient } = require('ldapts');
  const d = new CjsClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  await d.del('uid=' + req.body.user);
  res.end();
});

import { Client } from 'ldapts';
app.get('/ldapts-esm-plain', async (req, res) => {
  const f = new Client({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  await f.modify('uid=' + req.body.user, []);
  res.end();
});

import { Client as TsClient } from 'ldapts';
app.get('/ldapts-esm-alias', async (req, res) => {
  const g = new TsClient({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  await g.compare('uid=' + req.body.user, 'cn', 'x');
  res.end();
});

import * as ldaptsNs from 'ldapts';
app.get('/ldapts-esm-ns', async (req, res) => {
  const h = new ldaptsNs.Client({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  await h.add('uid=' + req.body.user, {});
  res.end();
});

const lt = require('ldapts');
app.get('/ldapts-cjs-ns', async (req, res) => {
  const e = new lt.Client({ url: 'ldap://a' });
  // ruleid: sast.js.ldap-dn-injection
  await e.search(req.query.base, { filter: '(objectClass=*)' });
  res.end();
});

// ---- the classic client, built from a top-level require ----
const ldap = require('ldapjs');
const client = ldap.createClient({ url: 'ldap://localhost' });

// look-alikes below every binding: the receiver itself must come from a client constructor
const api = new SearchApi();
app.get('/not-ldap', (req, res) => {
  // ok: sast.js.ldap-dn-injection
  api.bind('uid=' + req.body.user, req.body.pw, () => {});
  // ok: sast.js.ldap-dn-injection
  api.search(req.query.base, {}, () => {});
  // ok: sast.js.ldap-dn-injection
  client.exop(req.body.oid, () => {});
  res.end();
});

// the old name-based receiver check missed a client that is simply called something else
app.get('/renamed', (req, res) => {
  const c = ldap.createClient({ url: 'ldap://localhost' });
  // ruleid: sast.js.ldap-dn-injection
  c.bind('uid=' + req.body.user, req.body.pw, () => {});
  res.end();
});

app.get('/multiline', (req, res) => {
  client.search(
    // ruleid: sast.js.ldap-dn-injection
    req.query.base,
    { filter: '(objectClass=*)' },
    () => {}
  );
  client.bind(
    // ruleid: sast.js.ldap-dn-injection
    'uid=' + req.body.user,
    req.body.pw,
    () => {}
  );
  res.end();
});

// ---- sanitizers: each binding form of the ldap-escape package, weakest binding first (#6 item 1) ----
app.get('/esc-lookalikes', (req, res) => {
  const dn = (v) => v;
  // ruleid: sast.js.ldap-dn-injection
  client.bind('uid=' + dn(req.body.user) + ',ou=people', req.body.pw, () => {});
  const fakeEsc = makeEscaper();
  // ruleid: sast.js.ldap-dn-injection
  client.bind('uid=' + fakeEsc.dn(req.body.user) + ',ou=people', req.body.pw, () => {});
  const clean = (v) => v;
  // ruleid: sast.js.ldap-dn-injection
  client.bind('uid=' + clean(req.body.user) + ',ou=people', req.body.pw, () => {});
  res.end();
});

import { dn } from 'ldap-escape';
app.get('/esc-esm-plain', (req, res) => {
  // ok: sast.js.ldap-dn-injection
  client.bind('uid=' + dn(req.body.user) + ',ou=people', req.body.pw, () => {});
  res.end();
});

import { dn as escapeDn } from 'ldap-escape';
app.get('/esc-esm-alias', (req, res) => {
  // ok: sast.js.ldap-dn-injection
  client.bind('uid=' + escapeDn(req.body.user) + ',ou=people', req.body.pw, () => {});
  // ok: sast.js.ldap-dn-injection
  client.search(escapeDn`ou=${req.query.ou},dc=ex`, { filter: '(objectClass=*)' }, () => {});
  res.end();
});

import * as escNs from 'ldap-escape';
app.get('/esc-esm-ns', (req, res) => {
  // ok: sast.js.ldap-dn-injection
  client.bind('uid=' + escNs.dn(req.body.user) + ',ou=people', req.body.pw, () => {});
  res.end();
});

import escDefault from 'ldap-escape';
app.get('/esc-esm-default', (req, res) => {
  // ok: sast.js.ldap-dn-injection
  client.bind('uid=' + escDefault.dn(req.body.user) + ',ou=people', req.body.pw, () => {});
  res.end();
});

// ---- things that are NOT the package, above the require of it ----
app.get('/fake-obj', (req, res) => {
  // a local object that happens to be called ldapEscape is not the package
  const ldapEscape = { dn: (x) => x };
  // ruleid: sast.js.ldap-dn-injection
  client.bind('uid=' + ldapEscape.dn(req.body.user) + ',ou=people', req.body.pw, () => {});
  res.end();
});

function escapeLdapDn(v) { return v; }

app.get('/fake-fn', (req, res) => {
  // ruleid: sast.js.ldap-dn-injection
  client.bind('uid=' + escapeLdapDn(req.body.user) + ',ou=people', req.body.pw, () => {});
  res.end();
});

const ldapEscape = require('ldap-escape');

app.post('/dn', (req, res) => {
  // ruleid: sast.js.ldap-dn-injection
  client.bind('uid=' + req.body.user + ',ou=people,dc=ex,dc=com', req.body.pw, () => {});
  // ruleid: sast.js.ldap-dn-injection
  client.search(req.query.base, { filter: '(objectClass=*)' }, () => {});
  // ruleid: sast.js.ldap-dn-injection
  client.del('uid=' + req.body.user + ',ou=people', () => {});
  // ok: sast.js.ldap-dn-injection
  client.bind('uid=' + ldapEscape.dn(req.body.user) + ',ou=people', pw, () => {});
  // ok: sast.js.ldap-dn-injection
  client.search('dc=ex,dc=com', { filter: '(objectClass=*)' }, () => {});
  // ok: sast.js.ldap-dn-injection
  client.search(ldapEscape.dn`ou=${req.query.ou},dc=ex`, { filter: '(objectClass=*)' }, () => {});
  // ruleid: sast.js.ldap-dn-injection
  client.bind('uid=' + ldapEscape.dn(req.body.user) + ',ou=' + req.body.ou, pw, () => {});
  // ok: sast.js.ldap-dn-injection
  client.bind('uid=' + escapeDn(req.body.user) + ',ou=people', pw, () => {});
  // ok: sast.js.ldap-dn-injection
  client.search('dc=ex,dc=com', { filter: '(uid=' + req.query.uid + ')' }, () => {});
  // ok: sast.js.ldap-dn-injection
  client.compare('uid=jdoe,ou=people', 'cn', req.body.value, () => {});
  res.end();
});

app.get('/shadowed', (req, res) => {
  // inside this handler ldapEscape is a local object again, even though the package is required above
  const ldapEscape = { dn: (x) => x };
  // ruleid: sast.js.ldap-dn-injection
  client.bind('uid=' + ldapEscape.dn(req.body.user) + ',ou=people', req.body.pw, () => {});
  res.end();
});
