const libxmljs = require('libxmljs');
const libxml2 = require('libxmljs2');
const { parseXmlString } = require('libxmljs2');

function a(xml) {
  // ruleid: sast.js.libxml-noent
  return libxmljs.parseXml(xml, { noent: true });
}

function b(xml) {
  // ruleid: sast.js.libxml-noent
  return libxml2.parseXmlString(xml, { noent: true, nonet: false });
}

function c(xml) {
  // ruleid: sast.js.libxml-noent
  return parseXmlString(xml, { dtdload: true, noent: true });
}

function safeA(xml) {
  // ok: sast.js.libxml-noent
  return libxmljs.parseXml(xml);
}

function safeB(xml) {
  // ok: sast.js.libxml-noent
  return libxml2.parseXmlString(xml, { noent: false, nonet: true });
}

function safeC(xml) {
  // ok: sast.js.libxml-noent
  return libxmljs.parseXml(xml, { nonet: true });
}

function safeD(xml, opts) {
  // ok: sast.js.libxml-noent
  return somethingElse.parse(xml, { noent: true });
}
