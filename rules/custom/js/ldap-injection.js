const ldap = require('ldapjs');
const ldapEscape = require('ldap-escape');
const ActiveDirectory = require('activedirectory');
const express = require('express');
const app = express();
const client = ldap.createClient({ url: 'ldap://localhost' });
const ad = new ActiveDirectory({});

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
