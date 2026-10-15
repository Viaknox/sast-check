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

// A module that creates a Fastify instance AND has an Express path: only the sink inside a callback registered on the
// Fastify instance is exempt, not every sink that sits between the instance and a later call on it
const fx = Fastify();
app.get('/between-1', async (req, res) => {
  try {
    await work();
  } catch (err) {
    // ruleid: sast.js.express-error-leak
    res.status(500).send(err);
  }
});
app.use((err, req, res, next) => {
  // ruleid: sast.js.express-error-leak
  res.status(500).send(err);
});
fx.get('/ok-1', async (request, reply) => {
  try {
    await work();
  } catch (err) {
    // ok: sast.js.express-error-leak
    reply.send(err);
  }
});
fx.route({
  method: 'GET',
  url: '/ok-2',
  handler: async (request, reply) => {
    try {
      await work();
    } catch (err) {
      // ok: sast.js.express-error-leak
      reply.send(err);
    }
  },
});
fx.setErrorHandler(async (error, request, reply) => {
  try {
    await work();
  } catch (err) {
    // ok: sast.js.express-error-leak
    reply.send(err);
  }
});
fx.get('/ok-3', function (request, reply) {
  work().catch(function (err) {
    // ok: sast.js.express-error-leak
    reply.send(err);
  });
});
fx.addHook('onRequest', (request, reply, done) => {
  work().catch((err) => reply.send(err));
});
// ok: sast.js.express-error-leak
fx.get('/ok-7', async (request, reply) => work().catch((err) => reply.send(err)));
fx.listen({ port: 3000 });

const fy = fastify();
app.get('/between-2', (req, res) => {
  // ruleid: sast.js.express-error-leak
  work().catch((err) => res.send(err));
});
fy.get('/ok-4', async (request, reply) => {
  try {
    await work();
  } catch (err) {
    // ok: sast.js.express-error-leak
    reply.send(err);
  }
});
fy.listen({ port: 3001 });

const fz = require('fastify')();
app.get('/between-3', async (req, res) => {
  try {
    await work();
  } catch (err) {
    // ruleid: sast.js.express-error-leak
    res.send(err);
  }
});
fz.get('/ok-5', async (request, reply) => {
  try {
    await work();
  } catch (err) {
    // ok: sast.js.express-error-leak
    reply.send(err);
  }
});
fz.listen({ port: 3002 });

// a plugin registered on the Fastify instance gets its own instance object
fx.register(async (instance) => {
  instance.get('/ok-6', async (request, reply) => {
    try {
      await work();
    } catch (err) {
      // ok: sast.js.express-error-leak
      reply.send(err);
    }
  });
});

// a non-Fastify object with a get() method does not get the exemption just because a Fastify instance exists
const router2 = makeRouter();
router2.get('/not-fastify', async (request, reply) => {
  try {
    await work();
  } catch (err) {
    // ruleid: sast.js.express-error-leak
    reply.send(err);
  }
});
