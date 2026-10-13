const nunjucks = require("nunjucks");

// ruleid: sast.js.nunjucks-autoescape-off
nunjucks.configure("views", { autoescape: false, express: app });

// ruleid: sast.js.nunjucks-autoescape-off
nunjucks.configure({ autoescape: false });

// ruleid: sast.js.nunjucks-autoescape-off
const env = new nunjucks.Environment(loader, { autoescape: false });

// ok: sast.js.nunjucks-autoescape-off
nunjucks.configure("views", { autoescape: true, express: app });

// ok: sast.js.nunjucks-autoescape-off
nunjucks.configure("views", { express: app });

// ok: sast.js.nunjucks-autoescape-off
const env2 = new nunjucks.Environment(loader, { trimBlocks: true });

// ok: sast.js.nunjucks-autoescape-off
other.configure("x", { autoescape: false });
