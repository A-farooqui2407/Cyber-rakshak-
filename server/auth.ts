import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "crypto";
import type { Request, Response, NextFunction } from "express";
import type { UserProfile, UserRole } from "./types";

const SESSION_SECRET =
  process.env.SESSION_SECRET || "cyberrakshak-dev-secret-change-in-production";

export interface AuthUser extends UserProfile {
  organization_id: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const derived = scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, "hex");
  if (derived.length !== expected.length) return false;
  return timingSafeEqual(derived, expected);
}

export function signToken(user: AuthUser, ttlSec = 60 * 60 * 12): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(
    JSON.stringify({
      sub: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
      organization: user.organization,
      organization_id: user.organization_id,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + ttlSec,
    })
  ).toString("base64url");
  const sig = createHmac("sha256", SESSION_SECRET).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
}

export function verifyToken(token: string): AuthUser | null {
  try {
    const [header, body, sig] = token.split(".");
    if (!header || !body || !sig) return null;
    const expected = createHmac("sha256", SESSION_SECRET).update(`${header}.${body}`).digest("base64url");
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return {
      id: payload.sub,
      email: payload.email,
      role: payload.role,
      name: payload.name,
      organization: payload.organization,
      organization_id: payload.organization_id,
    };
  } catch {
    return null;
  }
}

export function getBearer(req: Request): string | null {
  const header = req.headers.authorization;
  if (header && header.startsWith("Bearer ")) return header.slice(7);
  return null;
}

export function requireAuth(roles?: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = getBearer(req);
    const user = token ? verifyToken(token) : null;
    if (!user) {
      return res.status(401).json({ error: "Authentication required" });
    }
    if (roles && user.role !== "ADMIN" && !roles.includes(user.role)) {
      return res.status(403).json({ error: `Role ${user.role} cannot perform this action` });
    }
    req.user = user;
    next();
  };
}

export const DEMO_CREDENTIALS = [
  { email: "rahul.sharma@lexguard.com", password: "Admin@LexGuard1", role: "ADMIN" as UserRole },
  { email: "ananya.p@lexguard.com", password: "Analyst@LexGuard1", role: "ANALYST" as UserRole },
  { email: "vikram.s@lexguard.com", password: "Viewer@LexGuard1", role: "VIEWER" as UserRole },
];
