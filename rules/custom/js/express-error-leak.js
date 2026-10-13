const express = require('express');
const app = express();

app.get('/a', async (req, res) => {
  try {
    await work();
  } catch (err) {
    // ruleid: sast.js.express-error-leak
    res.status(500).send(err.stack);
  }
});

app.get('/b', async (req, res) => {
  try {
    await work();
  } catch (e) {
    // ruleid: sast.js.express-error-leak
    res.json(e);
  }
});

app.get('/c', (req, res) => {
  // ruleid: sast.js.express-error-leak
  work().catch((error) => res.status(500).end(error.stack));
});

app.use((err, req, res, next) => {
  // ruleid: sast.js.express-error-leak
  res.status(500).send(err);
});

app.use(function handler(err, req, res, next) {
  // ruleid: sast.js.express-error-leak
  res.status(500).json({ message: err.message, stack: err.stack });
});

app.get('/safe', async (req, res) => {
  try {
    await work();
  } catch (err) {
    console.error(err);
    // ok: sast.js.express-error-leak
    res.status(500).json({ error: 'Internal error' });
  }
});

app.use((err, req, res, next) => {
  logger.error(err);
  // ok: sast.js.express-error-leak
  res.status(500).send('Something went wrong');
});

app.get('/safe2', async (req, res) => {
  const data = await work();
  // ok: sast.js.express-error-leak
  res.json(data);
  // ok: sast.js.express-error-leak
  res.send(req.body);
});

app.get('/safe3', async (req, res) => {
  try {
    await work();
  } catch (err) {
    // ok: sast.js.express-error-leak
    res.status(400).json({ error: 'Bad input', code: 'E_BAD' });
  }
});

fastify.get('/x', async (request, reply) => {
  try {
    await work();
  } catch (err) {
    // ok: sast.js.express-error-leak
    reply.send(err);
    // ruleid: sast.js.express-error-leak
    reply.code(500).send(err.stack);
  }
});

// ruleid: sast.js.express-error-leak
app.use((err, req, res, next) => res.json(err));

// ok: sast.js.express-error-leak
app.use((data, req, res, next) => res.json(data));

// Express handlers may call their response "reply"; the name alone does not make it Fastify
app.get('/r1', async (req, reply) => {
  try {
    await work();
  } catch (err) {
    // ruleid: sast.js.express-error-leak
    reply.send(err);
  }
});

app.get('/r2', (req, reply) => {
  // ruleid: sast.js.express-error-leak
  work().catch((e) => reply.status(500).send(e));
});

router.use((err, req, reply, next) => {
  // ruleid: sast.js.express-error-leak
  reply.status(500).send(err);
});

// other shapes of the leak, and look-alikes
app.get('/s1', async (req, res) => {
  try {
    await work();
  } catch (err) {
    // ruleid: sast.js.express-error-leak
    res.status(500).send(err.message);
    // ruleid: sast.js.express-error-leak
    res.status(500).json({ error: err });
    // ruleid: sast.js.express-error-leak
    res.json({ trace: err.stack });
    // ok: sast.js.express-error-leak
    other.send(err);
    // ok: sast.js.express-error-leak
    res.log(err);
  }
});

app.get('/s2', (req, res) => {
  // ruleid: sast.js.express-error-leak
  work().catch(function (e) { res.send(e.stack); });
});

app.use(function (err, req, res, next) {
  // ruleid: sast.js.express-error-leak
  res.send(err.stack);
});

app.use((err, req, res, next) => {
  // ruleid: sast.js.express-error-leak
  res.send(err.stack);
});

app.use(async (err, req, res, next) => {
  // ruleid: sast.js.express-error-leak
  res.send(err.stack);
});

// Fastify is recognised from how the route is registered
const f = Fastify({ logger: true });
f.get('/a', async (request, reply) => {
  try {
    await work();
  } catch (err) {
    // ok: sast.js.express-error-leak
    reply.send(err);
  }
});

fastify.route({
  method: 'GET',
  url: '/b',
  handler: async (request, reply) => {
    try {
      await work();
    } catch (err) {
      // ok: sast.js.express-error-leak
      reply.code(500).send(err);
    }
  },
});

const inst = fastify({ logger: true });
inst.get('/d', async (request, reply) => {
  try {
    await work();
  } catch (err) {
    // ok: sast.js.express-error-leak
    reply.send(err);
  }
});

const server = require('fastify')();
server.post('/c', async (request, reply) => {
  try {
    await work();
  } catch (err) {
    // ok: sast.js.express-error-leak
    reply.send(err);
    // ruleid: sast.js.express-error-leak
    reply.send({ detail: err.message });
  }
});
