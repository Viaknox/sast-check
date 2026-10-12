import jwt from 'jsonwebtoken';
import { decode, verify } from 'jsonwebtoken';
import { decodeJwt } from 'jose';
import type { Request, Response, NextFunction } from 'express';

export function readUser(req: Request, res: Response, next: NextFunction): void {
  const token: string = req.headers.authorization!.split(' ')[1];
  // ruleid: sast.js.jwt-decode-unverified
  const claims = jwt.decode(token) as { sub: string; admin: boolean };
  if (claims.admin) {
    next();
    return;
  }
  res.status(403).end();
}

export const getRole = (token: string): string => {
  // ruleid: sast.js.jwt-decode-unverified
  const payload = jwt.decode(token, { json: true });
  return payload?.role as string;
};

export function weakVerify(token: string, key: string) {
  // ruleid: sast.js.jwt-decode-unverified
  return jwt.verify(token, key, { algorithms: ['none'] });
}

export function mixedVerify(token: string, key: string) {
  // ruleid: sast.js.jwt-decode-unverified
  return jwt.verify(token, key, { algorithms: ['HS256', 'none'] });
}

export function checkedDecode(token: string, key: string) {
  jwt.verify(token, key, { algorithms: ['RS256'] });
  // ok: sast.js.jwt-decode-unverified
  const claims = jwt.decode(token);
  return claims;
}

export const checkedArrow = async (token: string, key: string) => {
  const ok = await new Promise((resolve) => jwt.verify(token, key, {}, (e) => resolve(!e)));
  // ok: sast.js.jwt-decode-unverified
  const claims = jwt.decode(token);
  return ok ? claims : null;
};

export function strictVerify(token: string, key: string) {
  // ok: sast.js.jwt-decode-unverified
  return jwt.verify(token, key, { algorithms: ['RS256', 'ES256'] });
}

export function otpThenDecode(code: string, token: string) {
  const otp = new OtpChecker();
  otp.verify(code);
  // ruleid: sast.js.jwt-decode-unverified
  const claims = jwt.decode(token);
  return claims;
}

export function displayOnly(token: string) {
  // ok: sast.js.jwt-decode-unverified
  const info = decodeJwt(token);
  return info.exp;
}

export class AuthService {
  constructor(private key: string) {}

  check(token: string) {
    jwt.verify(token, this.key, { algorithms: ['RS256'] });
    // ok: sast.js.jwt-decode-unverified
    return jwt.decode(token);
  }

  async checkAsync(token: string) {
    const claims = await Promise.resolve(jwt.verify(token, this.key, { algorithms: ['RS256'] }));
    // ok: sast.js.jwt-decode-unverified
    return jwt.decode(token);
  }

  peek(token: string) {
    // ruleid: sast.js.jwt-decode-unverified
    return jwt.decode(token);
  }
}

export class DirectAuth {
  check(token: string, key: string) {
    verify(token, key, { algorithms: ['ES256'] });
    // ok: sast.js.jwt-decode-unverified
    return decode(token);
  }

  peek(token: string) {
    // ruleid: sast.js.jwt-decode-unverified
    return decode(token);
  }
}
