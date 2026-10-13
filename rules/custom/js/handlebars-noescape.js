const Handlebars = require("handlebars");

// ruleid: sast.js.handlebars-noescape
const t1 = Handlebars.compile(source, { noEscape: true });

// ruleid: sast.js.handlebars-noescape
const t2 = Handlebars.compile(tpl, { strict: true, noEscape: true });

// ruleid: sast.js.handlebars-noescape
const t3 = hbs.precompile(tpl, { noEscape: true, knownHelpers: {} });

// ok: sast.js.handlebars-noescape
const o1 = Handlebars.compile(source);

// ok: sast.js.handlebars-noescape
const o2 = Handlebars.compile(source, { noEscape: false });

// ok: sast.js.handlebars-noescape
const o3 = Handlebars.compile(source, { strict: true });

// ok: sast.js.handlebars-noescape
const o4 = other.render(source, { noEscape: true });

// ok: sast.js.handlebars-noescape
const o5 = someLib.compile(x, { noEscape: true });
