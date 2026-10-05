import { createHash } from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

import { InternalServerError, UnauthorizedError } from '../errors/index.js';
import { ALLOWED_ALGORITHMS, requireAuth, type AuthenticatedLocals } from './requireAuth.js';
import { getTokenRevocationService } from '../services/tokenRevocation.js';
import { timingSafeStringEqual } from '../lib/timingSafe.js';

interface AdminJwtPayload {
  role: string;
  [key: string]: unknown;
}

// #1266: constant-time comparison lives in src/lib/timingSafe.ts (SHA-256
// digests compared with crypto.timingSafeEqual, so key length is not leaked).

/**
 * Resolve the admin actor for a request without terminating the middleware
 * chain.
 *
 * Accepts the configured admin API key or a Bearer JWT carrying the `admin`
 * role (with a valid `exp`, an optional `admin` audience, and not revoked).
 *
 * @returns The actor identity (`admin-api-key`, the JWT `sub`/`email`, or
 * `admin-jwt`), or `null` when the caller is not an authenticated admin.
 */
export function resolveAdminActor(req: Request): string | null {
  const apiKey = req.header('x-admin-api-key');
  const configuredKey = process.env.ADMIN_API_KEY;
  if (apiKey && configuredKey && timingSafeStringEqual(apiKey, configuredKey)) {
    return 'admin-api-key';
  }

  const authHeader = req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return null;
  }

  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, secret, { algorithms: ALLOWED_ALGORITHMS }) as AdminJwtPayload;

    if (typeof payload.exp !== 'number') {
      return null;
    }

    if (payload.aud !== undefined && payload.aud !== 'admin') {
      return null;
    }

    const tokenHash = createHash('sha256').update(token).digest('hex');
    if (getTokenRevocationService().isRevoked(tokenHash)) {
      return null;
    }

    if (payload.role === 'admin') {
      return (payload.sub as string) || (payload.email as string) || 'admin-jwt';
    }
  } catch {
    // Not a verifiable admin token.
  }

  return null;
}

/**
 * Admin authentication middleware.
 *
 * Authenticates admin callers via an API key or a Bearer JWT with the
 * `admin` role. On success it sets `authenticatedAdmin` and `adminActor` in
 * `res.locals` so downstream routes can authorize cross-user actions and audit
 * log the actor.
 */
export function adminAuth(req: Request, res: Response, next: NextFunction): void {
  const actor = resolveAdminActor(req);
  if (actor) {
    res.locals.adminActor = actor;
    res.locals.authenticatedAdmin = true;
    next();
    return;
  }

  // Preserve the explicit misconfiguration signal for an admin Bearer attempt.
  if (req.header('Authorization')?.startsWith('Bearer ') && !process.env.JWT_SECRET) {
    next(new InternalServerError('JWT_SECRET not configured'));
    return;
  }

  next(new UnauthorizedError('Unauthorized: admin access required'));
}

/**
 * Authenticate either an ordinary user/service principal (via {@link requireAuth})
 * or an admin (admin API key or admin-role JWT).
 *
 * Admins are projected onto `authenticatedUser` with their actor id so a route
 * can share a single code path, while `authenticatedAdmin` and `adminActor`
 * stay set so privileged cross-user actions can be authorised and audited.
 */
export function requireAuthOrAdmin(
  req: Request,
  res: Response<unknown, AuthenticatedLocals>,
  next: NextFunction,
): void {
  const actor = resolveAdminActor(req);
  if (actor) {
    res.locals.authenticatedAdmin = true;
    res.locals.adminActor = actor;
    res.locals.authenticatedUser = { id: actor };
    next();
    return;
  }

  requireAuth(req, res, next);
}
