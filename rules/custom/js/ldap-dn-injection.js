const ldap = require('ldapjs');
const ldapEscape = require('ldap-escape');
const ActiveDirectory = require('activedirectory');
const express = require('express');
const app = express();
const client = ldap.createClient({ url: 'ldap://localhost' });
const ad = new ActiveDirectory({});

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
  res.end();
});
