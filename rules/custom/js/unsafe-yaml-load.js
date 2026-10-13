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

// ok: sast.js.unsafe-yaml-load
const SAFE_EXT = yaml.DEFAULT_SCHEMA.extend([new yaml.Type('!x', { kind: 'scalar' })]);

// ok: sast.js.unsafe-yaml-load
const cheerio = require('cheerio').load('<p>x</p>', { schema: 1 });
