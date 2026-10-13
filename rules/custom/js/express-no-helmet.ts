import express from "express";
import http from "http";

export function plain() {
  const app = express();
  app.get("/", (_req, res) => res.send("hi"));
  // ruleid: sast.js.express-no-helmet
  app.listen(3000);
}

export function typed() {
  const server: express.Express = express();
  server.use(express.json());
  // ruleid: sast.js.express-no-helmet
  server.listen(8080, () => console.log("up"));
}

export function conditional() {
  const api = express();
  api.get("/health", (_req, res) => res.send("ok"));
  if (require.main === module) {
    // ruleid: sast.js.express-no-helmet
    api.listen(4000);
  }
}

export function notExpress(handler: http.RequestListener) {
  const srv = http.createServer(handler);
  // ok: sast.js.express-no-helmet
  srv.listen(3002);
}

export function creatorOnly() {
  const app = express();
  // ok: sast.js.express-no-helmet
  return app;
}

export function appFromElsewhere() {
  const app = buildApp();
  // ok: sast.js.express-no-helmet
  app.listen(5000);
}
