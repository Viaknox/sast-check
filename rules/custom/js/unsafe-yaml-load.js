// How this fixture is ordered (read before editing):
// The rule decides what a name means from the require/import that comes BEFORE it in the file, and a require
// is stronger than an import. So each binding form is tested in its own region, weakest binding first.

// ---- look-alikes that are not js-yaml, above every js-yaml binding (#6 item 16) ----
const otherYaml = require('some-yaml-lib');

function otherA(text) {
  // ok: sast.js.unsafe-yaml-load
  return otherYaml.load(text, { schema: otherYaml.FULL_SCHEMA });
}

function otherB(text, anything) {
  // ok: sast.js.unsafe-yaml-load
  return anything.loadAll(text, null, { schema: anything.DEFAULT_FULL_SCHEMA });
}

function otherC(text) {
  const load = (t, o) => t;
  const DEFAULT_FULL_SCHEMA = {};
  // ok: sast.js.unsafe-yaml-load
  return load(text, { schema: DEFAULT_FULL_SCHEMA });
}

function otherD(text, SchemaThing) {
  const parse = makeParser();
  // ok: sast.js.unsafe-yaml-load
  return parse(text, { schema: SchemaThing.FULL_SCHEMA });
}

// ---- each way of reaching js-yaml, one region each ----
function chain(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return require('js-yaml').load(text, { schema: require('js-yaml').DEFAULT_FULL_SCHEMA });
}

function chainAll(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return require('js-yaml').loadAll(text, null, { schema: require('js-yaml').FULL_SCHEMA });
}

import { loadAll } from 'js-yaml';
function namedPlain(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return loadAll(text, { schema: jsYamlNs.FULL_SCHEMA });
}

function namedPlainThirdArg(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return loadAll(text, null, { schema: jsYamlNs.FULL_SCHEMA });
}

import { safeLoad as parseYaml } from 'js-yaml';
function namedAlias(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return parseYaml(text, { schema: jsYamlNs.DEFAULT_FULL_SCHEMA });
}

function namedAliasThirdArg(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return parseYaml(text, null, { schema: jsYamlNs.DEFAULT_FULL_SCHEMA });
}

function namedAliasThirdArgSafe(text) {
  // ok: sast.js.unsafe-yaml-load
  return parseYaml(text, null, { schema: jsYamlNs.CORE_SCHEMA });
}

import * as jsYamlNs from 'js-yaml';
function nsImport(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return jsYamlNs.load(text, { schema: jsYamlNs.DEFAULT_FULL_SCHEMA });
}

import jsYamlDefault from 'js-yaml';
function defaultImport(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return jsYamlDefault.safeLoadAll(text, null, { schema: jsYamlDefault.FULL_SCHEMA });
}

// ---- the classic requires ----
const yaml = require('js-yaml');
const jsYaml = require('js-yaml');
const jsTypes = require('js-yaml-js-types');
const { load, DEFAULT_FULL_SCHEMA } = require('js-yaml');

function parseA(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return yaml.load(text, { schema: yaml.DEFAULT_FULL_SCHEMA });
}

function parseB(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return jsYaml.loadAll(text, null, { schema: jsYaml.FULL_SCHEMA });
}

function parseC(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return load(text, { schema: DEFAULT_FULL_SCHEMA });
}

// ruleid: sast.js.unsafe-yaml-load
const EXT = yaml.DEFAULT_SCHEMA.extend(jsTypes.all);

// ruleid: sast.js.unsafe-yaml-load
const EXT2 = yaml.DEFAULT_SCHEMA.extend(require('js-yaml-js-types').function);

function safeA(text) {
  // ok: sast.js.unsafe-yaml-load
  return yaml.load(text);
}

function safeB(text) {
  // ok: sast.js.unsafe-yaml-load
  return yaml.load(text, { schema: yaml.CORE_SCHEMA });
}

function safeC(text) {
  // ok: sast.js.unsafe-yaml-load
  return yaml.load(text, { schema: yaml.JSON_SCHEMA, json: true });
}

// a method name outside the loader list is not a parse call
function safeD(text) {
  // ok: sast.js.unsafe-yaml-load
  return yaml.dump(text, { schema: yaml.FULL_SCHEMA });
}

// ok: sast.js.unsafe-yaml-load
const SAFE_EXT = yaml.DEFAULT_SCHEMA.extend([new yaml.Type('!x', { kind: 'scalar' })]);

// ok: sast.js.unsafe-yaml-load
const cheerio = require('cheerio').load('<p>x</p>', { schema: 1 });
