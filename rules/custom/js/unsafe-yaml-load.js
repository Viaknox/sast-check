// How this fixture is ordered (read before editing):
// The rule decides what a name means from the require/import that comes BEFORE it in the file, and a require
// is stronger than an import. So each binding form is tested in its own region, weakest binding first.

// ---- helper declared BEFORE its module binding (reverse source order, PR #11 review 3) ----
// Each name below is bound to js-yaml (or to something else) only AFTER the function that uses it.
// The arrow-function pair comes first, with its binding right after, so no earlier function covers it.
const revArrow = (text) => {
  // ruleid: sast.js.unsafe-yaml-load
  return revYamlC.load(text, { schema: revYamlC.FULL_SCHEMA });
};
const revYamlC = require("js-yaml");

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

function revForeign(text) {
  // ok: sast.js.unsafe-yaml-load
  return revForeignLib.load(text, { schema: revForeignLib.FULL_SCHEMA });
}
const revForeignLib = require("some-yaml-lib");

function revForeignImport(text) {
  // ok: sast.js.unsafe-yaml-load
  return revForeignB.load(text, { schema: revForeignB.FULL_SCHEMA });
}
import revForeignB from "not-js-yaml";

function revForeignNamed(text) {
  // ok: sast.js.unsafe-yaml-load
  return foreignLoad(text, { schema: someNs.FULL_SCHEMA });
}
import { foreignLoad } from "other-yaml";

// ---- each way of reaching js-yaml, one region each ----
function chain(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return require('js-yaml').load(text, { schema: require('js-yaml').DEFAULT_FULL_SCHEMA });
}

function chainAll(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return require('js-yaml').loadAll(text, null, { schema: require('js-yaml').FULL_SCHEMA });
}

function revNamedPlain(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return safeLoadAll(text, null, { schema: someNs.FULL_SCHEMA });
}
import { safeLoadAll } from "js-yaml";

function revNamedPlainTwoArgs(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return safeLoad(text, { schema: someNs.FULL_SCHEMA });
}
import { safeLoad } from "js-yaml";

function revNamedAliasThirdArg(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return revLoadB(text, null, { schema: someNs.FULL_SCHEMA });
}
import { safeLoadAll as revLoadB } from "js-yaml";

function revNamedImport(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return revLoadAll(text, { schema: someNs.FULL_SCHEMA });
}
import { loadAll as revLoadAll } from "js-yaml";

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

function revNsImport(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return revYamlE.load(text, { schema: revYamlE.FULL_SCHEMA });
}
import * as revYamlE from "js-yaml";

import * as jsYamlNs from 'js-yaml';
function nsImport(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return jsYamlNs.load(text, { schema: jsYamlNs.DEFAULT_FULL_SCHEMA });
}

function revDefaultImport(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return revYamlD.safeLoad(text, { schema: revYamlD.FULL_SCHEMA });
}
import revYamlD from "js-yaml";

import jsYamlDefault from 'js-yaml';
function defaultImport(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return jsYamlDefault.safeLoadAll(text, null, { schema: jsYamlDefault.FULL_SCHEMA });
}

function revRequire(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return revYaml.load(text, { schema: revYaml.FULL_SCHEMA });
}
const revYaml = require("js-yaml");

function revRequireThird(text) {
  // ruleid: sast.js.unsafe-yaml-load
  return revYamlB.loadAll(text, null, { schema: revYamlB.DEFAULT_FULL_SCHEMA });
}
const revYamlB = require("js-yaml");

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
