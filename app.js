import express /*{type Application, type Request, type Response, type NextFunction}*/ from 'express';
import http from 'node:http'
// import bodyParser from 'body-parser';
import cors/*, { type CorsOptions, type CorsOptionsDelegate }*/ from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
// import supabase from './supabase/supabase_server.js';
import crypto from 'crypto';
import { rateLimit } from 'express-rate-limit';
// import slowDown from 'express-slow-down';
// TODO: do more research on slowDown before npm i
// TODO: ^^^ remove slowDown b/c using rate-limiter-flexible instead
import { z } from 'zod';
import { supaAnon, supaWithToken } from './supabase/clients.js';
// ---------------
import apiRoutes from './routes/apiRoute.js';
import postsRoute from './routes/postsRoute.js';
import downloadResumeRoute from './routes/downloadResumeRoute.js';
import rateLimiter from './middleware/rateLimiter.js';
import { localLogger } from './helpers/localLogger.js';
import { redisSessionStore } from './helpers/redisSessionStore.js';
import { initLoginRateLimiter, limiterConsecutiveFailsByUsernameAndIP, limiterSlowBruteByIP, getUsernameIPkey } from './helpers/loginRateLimiter.js';
// ---------------
dotenv.config();
const port = process.env.PORT;
const IS_PROD = process.env.NODE_ENV === 'production';
// ---------------
const app = express();
// ---------------
const isProdEnv = process.env.NODE_ENV === 'production';
// Run behind proxy (Render) so req.secure & cookies honor X-Forwarded-Proto:
// https://expressjs.com/en/guide/behind-proxies.html
app.set("trust proxy", 1);
app.use(helmet({
	hsts: false,
	referrerPolicy: { policy: 'no-referrer' },
	crossOriginResourcePolicy: { policy: 'same-site' },
	contentSecurityPolicy: {
		useDefaults: true,
		directives: {
			defaultSrc: ["'none'"],
		},
		// ^Setting contentSecurityPolicy with default-src 'none' ensures that if the API ever returns HTML (error pages, debug output), the browser won’t auto-load any scripts/images/fonts from anywhere. This reduces XSS/XSSI blast radius without impacting fetch/XHR from myresumesiteexample.xyz (CSP applies to documents, not API responses consumed by fetch).
		// crossOriginResourcePolicy: 'same-site' tells browsers not to let other “sites” embed your responses as resources (e.g., <img src>, <script src>, <audio src>, or cross-site <iframe>). That blocks common data-leak vectors and drive-by inclusion attacks.
		// It does not block your frontend’s credentialed fetch/XHR from myresumesiteexample.xyz because those are CORS network requests, not resource embedding. Your CORS allowlist + credentials continues to govern client access.
	},
}));
if (isProdEnv) {
	app.use(helmet.hsts({ maxAge: 15552000, includeSubDomains: true, preload: true }));
}
app.use(express.json({ limit: '25kb' })); // or express.urlencoded({ extended: true })
app.use(express.urlencoded({ extended: false, limit: '25kb'}))
app.use(cookieParser());
// ---------------


const allowlist = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim().replace(/\/$/, '')) // normalize trailing slash
  .filter(Boolean);
if (!isProdEnv && allowlist.length === 0) {
  // Dev-safe defaults
  allowlist.push('http://localhost:4321', 'http://127.0.0.1:4321');
}



const corsDelegate = (req, cb) => {
	const requested = req.headers['access-control-request-headers'];
	const allowedHeaders =
	  typeof requested === 'string'
		? requested.split(',').map(h => h.trim())
		: ['Content-Type', 'Authorization', 'X-CSRF-Token'];
  
	cb(null, {
	//   origin: (origin, done) => done(null, !origin || allowlist.includes(origin)),
	origin: (origin, done) => {
		if (!origin) return done(null, true);
		try {
			const o = new URL(origin);
			const normalized = `${o.protocol}//${o.host}`;
			return done(null, allowlist.includes(normalized));
		} catch {
			return done(null, false);
		}
	  },
	  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
	  credentials: true, // produce Access-Control-Allow-Credentials: true
	  				//   https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Credentials
	  maxAge: 600,
	  exposedHeaders: ['Content-Disposition','RateLimit-Limit','RateLimit-Remaining','RateLimit-Reset','X-RateLimit-Limit','X-RateLimit-Remaining','X-RateLimit-Reset'],
	  allowedHeaders,
	//   exposedHeaders: ['Content-Disposition','X-RateLimit-Limit','X-RateLimit-Remaining'],
	//   allowedHeaders,
	});
};

// Express helper that safely appends without dupes
app.use((_, res, next) => { res.vary('Origin'); next(); });

// CORS (single source of truth)
app.use(cors(corsDelegate));
// explicit preflight handler ensures headers on 204 response (Express 5: use RegExp, not '*')
app.options(/.*/, cors(corsDelegate));


// Don't rate-limit preflights (OPTIONS carry no creds)
app.use((req, res, next) => (req.method === 'OPTIONS' ? res.sendStatus(204) : next()));
// Initialize Redis-backed login rate limiters (non-blocking start)
void initLoginRateLimiter().catch((e) => console.warn('[rate-limiter init error]', e?.message || e));



// Session config (idle + absolute lifetimes)
const SESSION_IDLE_TTL_SECONDS = Number(process.env.SESSION_IDLE_TTL_SECONDS || (IS_PROD ? 1800 : 7200)); // 30m prod, 2h dev
const SESSION_ABSOLUTE_LIFETIME_SECONDS = Number(process.env.SESSION_ABSOLUTE_LIFETIME_SECONDS || (IS_PROD ? 604800 : 2592000)); // 7d prod, 30d dev

const generalLimiter = rateLimit({ windowMs: 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false });
app.use(generalLimiter);
// Sliding idle expiration for any request carrying a session cookie
app.use(async (req, res, next) => {
	const sid = req.cookies?.sid;
	if (sid) {
		void redisSessionStore
		  .touch(sid, SESSION_IDLE_TTL_SECONDS)
		  .catch(err => console.warn('session touch failed', { err }));
	}	  
	// ^^ keeps the call non-blocking, silences the linter intentionally, and prevents unhandled rejections from taking down server
	next();
});

// --------------------------------
// --------------------------------
// -------------AIAC---------------
// ---------- CSRF (Signed Double-Submit Cookie) ----------
// const IS_PROD = process.env.NODE_ENV === 'production';
// const CSRF_COOKIE = '__Host-csrf_secret';
// const CSRF_HEADER = 'X-CSRF-Token';
// const IS_PROD = process.env.NODE_ENV === 'production';
const CSRF_COOKIE = IS_PROD ? '__Host-csrf_secret' : 'csrf_secret';
const CSRF_HEADER = 'X-CSRF-Token';
const CSRF_TTL_SECONDS = 300; // 5m

// const SUPABASE_URL = process.env.SUPABASE_URL;
// const SUPABASE_ANON = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_SAFE_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_SAFE_KEY;

// Added: fail fast if required envs are missing
if (!SUPABASE_URL || !SUPABASE_ANON) {
	console.error('Missing SUPABASE_URL or SUPABASE_ANON_KEY/SUPABASE_SAFE_KEY');
	process.exit(1);
}

// // In-memory session store (replace with Redis/DB in production)
// const sessions = new Map();

// // Added: basic expiry cleanup for stale sessions
// setInterval(() => {
// 	const now = Math.floor(Date.now()/1000);
// 	for (const [sid, s] of sessions) {
// 		if (s.expires_at && s.expires_at < now - 300) sessions.delete(sid);
// 	}
// }, 60_000).unref();

function b64url(buf) {
	return Buffer.from(buf).toString('base64url');
}

function timingSafeEq(a, b) {
	const ab = Buffer.from(a);
	const bb = Buffer.from(b);
	if (ab.length !== bb.length) return false;
	return crypto.timingSafeEqual(ab, bb);
}
function getOrSetCsrfSecret(req, res) {
	let secret = req.cookies?.[CSRF_COOKIE];
	if (!secret) {
		secret = b64url(crypto.randomBytes(32));
		res.cookie(CSRF_COOKIE, secret, {
			httpOnly: true,
			secure: IS_PROD,  // false in dev ;; In dev over http, SameSite=None cookies may be rejected by some browsers
			sameSite: IS_PROD ? 'none' : 'lax', // 'lax' works across localhost ports
			path: '/',
		});
	}
	return secret;
}
function sign(secret, payload) {
	return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}
function issueCsrfToken(req, res) {
	const secret = getOrSetCsrfSecret(req, res);
	const sid = req.cookies?.sid ?? 'anon';
	const ts = Math.floor(Date.now() / 1000);
	const nonce = b64url(crypto.randomBytes(16));
	const payload = `${sid}.${ts}.${nonce}`;
	const mac = sign(secret, payload);
	return `${payload}.${mac}`; // sid.ts.nonce.mac
}
function verifyCsrfToken(req) {
	const hdr = (req.header(CSRF_HEADER) || '').trim();
	if (!hdr) return false;
	const parts = hdr.split('.');
	if (parts.length !== 4) return false;
	const [sidInToken, tsStr, nonce, mac] = parts;
	const ts = Number(tsStr);
	if (!Number.isFinite(ts)) return false;
	if (Math.abs(Math.floor(Date.now() / 1000) - ts) > CSRF_TTL_SECONDS) return false;

	const secret = req.cookies?.[CSRF_COOKIE];
	if (!secret) return false;

	const sid = req.cookies?.sid ?? 'anon';
	if (sid !== sidInToken) return false;

	const payload = `${sidInToken}.${ts}.${nonce}`;
	const expected = sign(secret, payload);
	return timingSafeEq(expected, mac);
}

function requireCsrf(req, res, next) {
	if (!verifyCsrfToken(req)) return res.status(403).json({ error: { code: 'CSRF_INVALID', message: 'Invalid CSRF token' } });
	next();
}

// Added: enforce CSRF on all state-changing methods globally
app.use((req, res, next) => {
	const m = req.method;
	if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return next();
	requireCsrf(req, res, next);
});

// Issue token for client to use on state-changing requests
app.get('/auth/csrf', (req, res) => {
	const csrfToken = issueCsrfToken(req, res);
	res.setHeader('Cache-Control', 'no-store');
	res.json({ csrfToken });
});

// Input validation schemas and brute-force slowdown
const LoginSchema = z.object({ email: z.string().email(), password: z.string().min(6) });
// const authSlowdown = slowDown({
// 	windowMs: 15 * 60 * 1000,
// 	delayAfter: 5,
// 	delayMs: (hits) => Math.min(hits * 250, 3000),
// });
function setSidCookie(res, sid) {
	res.cookie('sid', sid, {
		httpOnly: true,
		secure: IS_PROD,     // false in dev ;; In dev over http, SameSite=None cookies may be rejected by some browsers
		sameSite: IS_PROD ? 'none' : 'lax', // 'lax' works across localhost ports
		path: '/',
	});
}

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 50 });

app.post('/auth/login', authLimiter, /*authSlowdown, */requireCsrf, async (req, res) => {
	const parsed = LoginSchema.safeParse(req.body ?? {});
	if (!parsed.success) return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid credentials payload' } });
	const { email, password } = parsed.data;

	// node-rate-limiter-flexible protection (username+IP and IP per day)
	const ipAddr = req.ip;
	const usernameIPkey = getUsernameIPkey(email, ipAddr);
	try {
		const [resUsernameAndIP, resSlowByIP] = await Promise.all([
			limiterConsecutiveFailsByUsernameAndIP.get(usernameIPkey),
			limiterSlowBruteByIP.get(ipAddr),
		]);
		let retrySecs = 0;
		if (resSlowByIP && resSlowByIP.consumedPoints > Number(process.env.RLF_MAX_FAILS_PER_IP_PER_DAY || 100)) {
			retrySecs = Math.round(resSlowByIP.msBeforeNext / 1000) || 1;
		} else if (resUsernameAndIP && resUsernameAndIP.consumedPoints > Number(process.env.RLF_MAX_CONSEC_FAILS_USERNAME_IP || 10)) {
			retrySecs = Math.round(resUsernameAndIP.msBeforeNext / 1000) || 1;
		}
		if (retrySecs > 0) {
			res.set('Retry-After', String(retrySecs));
			return res.status(429).json({ error: { code: 'TOO_MANY_REQUESTS', message: 'Too many attempts. Try later.' } });
		}
	} catch (e) {
		// If rate limiter storage fails, proceed but log
		console.warn('[rate-limit check error]', e?.message || e);
	}

	const { data, error } = await supaAnon().auth.signInWithPassword({ email, password });
	if (error || !data?.session) {
		try {
			const promises = [limiterSlowBruteByIP.consume(ipAddr)];
			// Only count consecutive fails for existing users to avoid user enumeration amplification
			promises.push(limiterConsecutiveFailsByUsernameAndIP.consume(usernameIPkey));
			await Promise.all(promises);
		} catch (rlRejected) {
			if (rlRejected && typeof rlRejected === 'object' && 'msBeforeNext' in rlRejected) {
				res.set('Retry-After', String(Math.round((rlRejected.msBeforeNext || 0) / 1000)) || '1');
				return res.status(429).json({ error: { code: 'TOO_MANY_REQUESTS', message: 'Too many attempts. Try later.' } });
			}
		}
		return res.status(401).json({ error: 'invalid credentials' });
	}

	const { access_token, refresh_token, expires_at } = data.session;
	const sid = b64url(crypto.randomBytes(32));
	// sessions.set(sid, { access_token, refresh_token, expires_at });
	await redisSessionStore.set(
		sid,
		{ access_token, refresh_token, expires_at },
		SESSION_IDLE_TTL_SECONDS,
		SESSION_ABSOLUTE_LIFETIME_SECONDS
	);
	setSidCookie(res, sid);
	// reset consecutive fails on success
	try { await limiterConsecutiveFailsByUsernameAndIP.delete(usernameIPkey); } catch {}
	localLogger('auth-in request successful', {email})
	res.status(204).end();	
});

app.post('/auth/logout', authLimiter, /*authSlowdown, */requireCsrf, async (req, res) => {
	const sid = req.cookies?.sid;
	// const sess = sid ? sessions.get(sid) : null;
	// if (sess)
	if (sid) {
		const sess = await redisSessionStore.get(sid);
		if (sess) {
			await supaWithToken(sess.access_token).auth.signOut();
			localLogger('auth-out from supabase using redis session store')
		}
		// sessions.delete(sid);
		await redisSessionStore.del(sid);
		localLogger('sid deleted from redis session store')
	}
	// Clear cookie using the same attributes used when setting it
	res.clearCookie('sid', { path: '/', sameSite: IS_PROD ? 'none' : 'lax', secure: IS_PROD, httpOnly: true });
	localLogger('auth-out request successful')
	res.status(204).end();
});

// Refresh access token using stored refresh_token
app.post('/auth/refresh', authLimiter, /*authSlowdown, */requireCsrf, async (req, res) => {
	const sid = req.cookies?.sid;
	if (!sid) return res.status(401).json({ error: 'not authenticated' });
	// const sess = sessions.get(sid);
	const sess = await redisSessionStore.get(sid);
	if (!sess) return res.status(401).json({ error: 'not authenticated' });

	const { data, error } = await supaAnon().auth.refreshSession({ refresh_token: sess.refresh_token });
	if (error || !data?.session) {
		// sessions.delete(sid);
		await redisSessionStore.del(sid);
		// Clear cookie using the same attributes used when setting it
		res.clearCookie('sid', { path: '/', sameSite: IS_PROD ? 'none' : 'lax', secure: IS_PROD, httpOnly: true });
		return res.status(401).json({ error: 'refresh failed' });
	}
	const { access_token, refresh_token, expires_at } = data.session;
	// sessions.set(sid, { access_token, refresh_token, expires_at });
	await redisSessionStore.set(sid,{ access_token, refresh_token, expires_at }, SESSION_IDLE_TTL_SECONDS, SESSION_ABSOLUTE_LIFETIME_SECONDS);
	res.status(204).end();
});

// Verify current session (does not leak tokens)
app.get('/auth/session', authLimiter, async (req, res) => {
	const sid = req.cookies?.sid;
	if (!sid) return res.status(401).json({ authenticated: false });
	// const sess = sessions.get(sid);
	const sess = await redisSessionStore.get(sid);
	if (!sess) return res.status(401).json({ authenticated: false });

	// Optionally auto-refresh if near expiry
	const now = Math.floor(Date.now() / 1000);
	if (sess.expires_at && now > (sess.expires_at - 30)) {
		const { data, error } = await supaAnon().auth.refreshSession({ refresh_token: sess.refresh_token });
		if (error || !data?.session) {
			// sessions.delete(sid);
			await redisSessionStore.del(sid);
			// Clear cookie using the same attributes used when setting it
			res.clearCookie('sid', { path: '/', sameSite: IS_PROD ? 'none' : 'lax', secure: IS_PROD, httpOnly: true });
			return res.status(401).json({ authenticated: false });
		}
		const { access_token, refresh_token, expires_at } = data.session;
		// sessions.set(sid, { access_token, refresh_token, expires_at });
		await redisSessionStore.set(sid, { access_token, refresh_token, expires_at }, SESSION_IDLE_TTL_SECONDS, SESSION_ABSOLUTE_LIFETIME_SECONDS);
	}

	const current = await redisSessionStore.get(sid);
	if (!current) return res.status(401).json({ authenticated: false });

	const { data, error } = await supaWithToken(current.access_token).auth.getUser();
	if (error) return res.status(401).json({ authenticated: false });
	res.json({ authenticated: true, user: data.user });
});
// -------------AIAC---------------
// --------------------------------
// --------------------------------

app.use('/api', apiRoutes);
app.use('/api/posts', postsRoute);
app.use('/download/resume', rateLimiter, downloadResumeRoute);

app.get('/', (_, res) => {
	res.send('Hello World!');
});

// lightweight health check
app.get('/health', (_, res) => res.status(200).json({ status: 'ok' }));

app.use((_, res) => res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found' } }));
app.use((err, req, res, next) => {
  console.error('[Unhandled error]', err);
  res.status(500).json({ error: { code: 'INTERNAL', message: 'Internal server error' } });
});

// app.listen(port, () => {
// 	console.log(`Starting server on port: ${port}`);
// });

const server = http.createServer(app);

server.headersTimeout = 62000;   // 62s
server.keepAliveTimeout = 61000; // 61s
// how long the server keeps the TCP connection idle waiting for the next request before destroying the socket
// For apps behind load balancers (ALB/ELB, GCP, etc.), it’s common to set keepAliveTimeout slightly above the LB’s idle timeout (e.g., 61s for a 60s LB) so the server doesn’t close first, avoiding intermittent 502/ECONNRESET issues.
// Also, make headersTimeout a bit greater than keepAliveTimeout (e.g., 62s vs 61s) so when a client reuses a keep-alive connection, there’s a small grace period to deliver the next request’s headers. Your code currently has headersTimeout (60s) below keepAliveTimeout (61s); flip that to follow the common guidance.
server.requestTimeout = 30000;   // 30s
server.listen(port, () => {
	console.log(`Starting server on port: ${port}`);
})

// --------------------------------
// graceful shutdown

const gracefulShutdown = (signal) => {
	console.log(`Received ${signal}, shutting down gracefully...`);

	console.log('Server closed');
	process.exit(0);


	// const FORCE = setTimeout(() => {
	// 	console.error('Graceful shutdown timed out — forcing close.');
	// 	// try { redis.destroy(); } catch {}
	// 	process.exit(1);
	//   }, 30_000).unref();

	// app.close(() => {
	// 	// try { if (redis.isOpen) await redis.close(); } catch (e) { console.error('redis.close error:', e); }
    // 	clearTimeout(FORCE);

	// 	console.log('Server closed');
	// 	process.exit(0);
	// });
};

process.on('SIGINT',  () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
// sigterm used for kubernetes