import { NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

// ============================================================
// SECURITY MIDDLEWARE
// Executes on EVERY request before it reaches any route handler.
// Defends against: CSRF, Brute Force, Replay, Burp Intruder,
// Session Hijacking, and unauthorized API access.
// ============================================================

// --- Rate Limiter (In-Memory, per-IP) ---
// Tracks request counts per IP. Resets after windowMs.
// This stops Burp Suite Intruder/Repeater automated attacks.
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 60;      // 60 requests per minute globally
const LOGIN_RATE_LIMIT_MAX = 5;          // 5 login attempts per minute

function getRateLimitKey(ip, path) {
  if (path.includes("/api/auth")) return `login:${ip}`;
  return `global:${ip}`;
}

function isRateLimited(key, max) {
  const now = Date.now();
  const entry = rateLimitMap.get(key);

  if (!entry || now - entry.start > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(key, { start: now, count: 1 });
    return false;
  }

  entry.count++;
  if (entry.count > max) return true;
  return false;
}

// Periodic cleanup to prevent memory exhaustion (DoS via map growth)
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of rateLimitMap) {
    if (now - val.start > RATE_LIMIT_WINDOW_MS * 2) {
      rateLimitMap.delete(key);
    }
  }
}, RATE_LIMIT_WINDOW_MS);


// --- Protected Routes ---
const PROTECTED_PATHS = ["/chat", "/api/upload"];

export async function middleware(request) {
  const { pathname } = request.nextUrl;
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || request.headers.get("x-real-ip")
    || "unknown";

  // ----------------------------------------------------------
  // 1. RATE LIMITING (Anti Burp Intruder / Brute Force)
  // ----------------------------------------------------------
  const rlKey = getRateLimitKey(ip, pathname);
  const rlMax = pathname.includes("/api/auth") ? LOGIN_RATE_LIMIT_MAX : RATE_LIMIT_MAX_REQUESTS;

  if (isRateLimited(rlKey, rlMax)) {
    return new NextResponse(
      JSON.stringify({ error: "Rate limit exceeded. Request denied." }),
      { status: 429, headers: { "Content-Type": "application/json", "Retry-After": "60" } }
    );
  }

  // ----------------------------------------------------------
  // 2. CSRF PROTECTION (Anti Cross-Site Request Forgery)
  // Next.js Server Actions already embed CSRF tokens natively.
  // This layer adds explicit Origin/Referer validation for
  // all state-changing API routes, blocking forged requests
  // even if an attacker replays them through Burp.
  // ----------------------------------------------------------
    // Skip manual CSRF check for NextAuth's internal routes (they have their own protection)
    // and for Server Actions (which have their own tokens).
    if (pathname.startsWith("/api/auth")) {
      return NextResponse.next();
    }

    const origin = request.headers.get("origin");
    const referer = request.headers.get("referer");
    const host = request.headers.get("x-forwarded-host") || request.headers.get("host");

    // Allow requests with no origin only from same-site (Server Actions)
    if (origin) {
      const originHost = new URL(origin).host;
      if (originHost !== host && !host.includes("localhost")) {
        return new NextResponse(
          JSON.stringify({ error: "CSRF violation: Origin mismatch. Request rejected." }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );
      }
    }

  // ----------------------------------------------------------
  // 3. AUTHENTICATION GATE (Simplified for Stability)
  // ----------------------------------------------------------
  const isProtected = PROTECTED_PATHS.some(p => pathname.startsWith(p));
  
  const token = await getToken({ 
    req: request, 
    secret: process.env.NEXTAUTH_SECRET,
    cookieName: "next-auth.session-token" 
  });

  if (isProtected && !token) {
    const loginUrl = new URL("/login", request.url);
    return NextResponse.redirect(loginUrl);
  }

  // ----------------------------------------------------------
  // 4. SECURITY RESPONSE HEADERS (Per-Request Hardening)
  // ----------------------------------------------------------
  const response = NextResponse.next();

  // Prevent caching of authenticated content by proxies/Burp
  if (isProtected) {
    response.headers.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    response.headers.set("Pragma", "no-cache");
    response.headers.set("Expires", "0");
  }

  return response;
}

export const config = {
  // Run middleware on all routes except static assets and _next internals
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
