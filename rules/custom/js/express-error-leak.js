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
