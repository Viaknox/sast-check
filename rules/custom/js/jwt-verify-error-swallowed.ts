import jwt from 'jsonwebtoken';
import type { Request, Response } from 'express';

export function swallowEmpty(token: string, key: string) {
  try {
    jwt.verify(token, key, { algorithms: ['RS256'] });
  } catch (e) {
  }
  // ruleid: sast.js.jwt-verify-error-swallowed
  const claims = jwt.decode(token) as { admin: boolean };
  return claims.admin;
}

export function swallowLogOnly(token: string, key: string) {
  try {
    jwt.verify(token, key, { algorithms: ['RS256'] });
  } catch (err) {
    console.warn('bad token', err);
  }
  // ruleid: sast.js.jwt-verify-error-swallowed
  return jwt.decode(token);
}

export function callbackThenDecode(req: Request, res: Response, key: string) {
  const token = String(req.headers.authorization);
  jwt.verify(token, key, (err, _decoded) => {
    if (err) res.status(401).end();
  });
  // ruleid: sast.js.jwt-verify-error-swallowed
  const claims = jwt.decode(token);
  return claims;
}

export function callbackFunctionThenDecode(token: string, key: string) {
  jwt.verify(token, key, {}, function (err) {
    if (err) throw err;
  });
  // ruleid: sast.js.jwt-verify-error-swallowed
  return jwt.decode(token);
}

export function rethrows(token: string, key: string) {
  try {
    jwt.verify(token, key, { algorithms: ['RS256'] });
  } catch (e) {
    console.error(e);
    throw e;
  }
  // ok: sast.js.jwt-verify-error-swallowed
  return jwt.decode(token);
}

export function returnsOnFailure(token: string, key: string) {
  try {
    jwt.verify(token, key, { algorithms: ['RS256'] });
  } catch (e) {
    return null;
  }
  // ok: sast.js.jwt-verify-error-swallowed
  return jwt.decode(token);
}

export function decodeInsideCallback(token: string, key: string, done: (c: unknown) => void) {
  jwt.verify(token, key, (err) => {
    if (err) return done(null);
    // ok: sast.js.jwt-verify-error-swallowed
    done(jwt.decode(token));
  });
}

export function decodeInsideTry(token: string, key: string) {
  try {
    jwt.verify(token, key, { algorithms: ['RS256'] });
    // ok: sast.js.jwt-verify-error-swallowed
    return jwt.decode(token);
  } catch (e) {
    return null;
  }
}

export function otherTokenAfterTry(a: string, b: string, key: string) {
  try {
    jwt.verify(a, key, { algorithms: ['RS256'] });
  } catch (e) {
  }
  // ok: sast.js.jwt-verify-error-swallowed
  return jwt.decode(b);
}
