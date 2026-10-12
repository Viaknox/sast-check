const https = require("https");
const axios = require("axios");
const got = require("got");

// ruleid: sast.js.tls-reject-unauthorized-off
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// ruleid: sast.js.tls-reject-unauthorized-off
process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

// ruleid: sast.js.tls-reject-unauthorized-off
const agent = new https.Agent({ rejectUnauthorized: false });

// ruleid: sast.js.tls-reject-unauthorized-off
axios.get(url, { httpsAgent: new https.Agent({ keepAlive: true, rejectUnauthorized: false }) });

// ruleid: sast.js.tls-reject-unauthorized-off
got(url, { https: { rejectUnauthorized: false } });

// ruleid: sast.js.tls-reject-unauthorized-off
https.globalAgent.options.rejectUnauthorized = false;

// ok: sast.js.tls-reject-unauthorized-off
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";

// ok: sast.js.tls-reject-unauthorized-off
const a2 = new https.Agent({ rejectUnauthorized: true, ca });

// ok: sast.js.tls-reject-unauthorized-off
const a3 = new https.Agent({ keepAlive: true });

// ok: sast.js.tls-reject-unauthorized-off
process.env.NODE_ENV = "0";

// ok: sast.js.tls-reject-unauthorized-off
const dbOpts = { ssl: { rejectUnauthorized: false } };
