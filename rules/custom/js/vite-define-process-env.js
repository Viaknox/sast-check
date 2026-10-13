const webpack = require("webpack");

module.exports = {
  // ruleid: sast.js.vite-define-process-env
  define: { "process.env": process.env },
};

module.exports.b = {
  // ruleid: sast.js.vite-define-process-env
  define: { "process.env": JSON.stringify(process.env) },
};

module.exports.plugins = [
  // ruleid: sast.js.vite-define-process-env
  new webpack.DefinePlugin({ "process.env": JSON.stringify(process.env) }),
];

module.exports.d = {
  // ruleid: sast.js.vite-define-process-env
  define: { 'process.env': { ...process.env } },
};

module.exports.ok1 = {
  // ok: sast.js.vite-define-process-env
  define: { "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV) },
};

module.exports.ok2 = {
  // ok: sast.js.vite-define-process-env
  define: { "process.env": { NODE_ENV: "production" } },
};

module.exports.ok3 = [
  // ok: sast.js.vite-define-process-env
  new webpack.DefinePlugin({ "process.env.API_URL": JSON.stringify(process.env.API_URL) }),
];

module.exports.ok4 = {
  // ok: sast.js.vite-define-process-env
  define: { __VERSION__: JSON.stringify(process.env.npm_package_version) },
};
