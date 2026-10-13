const crypto = require('crypto');

function check(req, stored) {
  // ruleid: sast.js.timing-unsafe-compare
  if (req.body.password === stored.passwordHash) return true;
  // ruleid: sast.js.timing-unsafe-compare
  if (req.headers['x-api-key'] === process.env.API_KEY) return true;
  // ruleid: sast.js.timing-unsafe-compare
  if (providedSignature !== expectedSignature) return false;
  // ruleid: sast.js.timing-unsafe-compare
  return hmac.digest('hex') == req.headers['x-hub-signature'];
}

function tokenCheck(token, saved) {
  // ok: sast.js.timing-unsafe-compare
  return token === saved;
}

app.post('/hook', (req, res) => {
  const sig = computeSig(req.rawBody);
  // ruleid: sast.js.timing-unsafe-compare
  if (sig !== storedSignature) return res.sendStatus(401);
});

function confirmForm(form) {
  // ok: sast.js.timing-unsafe-compare
  if (form.value() !== form.valueOf(newPassword)) return { kind: 'notSame' };
}

function safe(token, secret, password, other) {
  // ok: sast.js.timing-unsafe-compare
  if (token === null) return false;
  // ok: sast.js.timing-unsafe-compare
  if (token === undefined) return false;
  // ok: sast.js.timing-unsafe-compare
  if (password === '') return false;
  // ok: sast.js.timing-unsafe-compare
  if (typeof secret === 'string') return true;
  // ok: sast.js.timing-unsafe-compare
  if (token.length !== other.length) return false;
  // ok: sast.js.timing-unsafe-compare
  if (tokenType === 'bearer') return true;
  // ok: sast.js.timing-unsafe-compare
  if (mode === 'secret') return true;
  // ok: sast.js.timing-unsafe-compare
  return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(other));
}
