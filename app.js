import express /*{type Application, type Request, type Response, type NextFunction}*/ from 'express';
// import bodyParser from 'body-parser';
import cors/*, { type CorsOptions, type CorsOptionsDelegate }*/ from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
// import supabase from './supabase/supabase_server.js';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { rateLimit } from 'express-rate-limit';
// ---------------
import apiRoutes from './routes/apiRoute.js';
import postsRoute from './routes/postsRoute.js';
import downloadResumeRoute from './routes/downloadResumeRoute.js';
import rateLimiter from './middleware/rateLimiter.js';
import { localLogger } from './helpers/localLogger.js';
// ---------------
dotenv.config();
const port = process.env.PORT;

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
	  origin: (origin, done) => done(null, !origin || allowlist.includes(origin)),
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

const generalLimiter = rateLimit({ windowMs: 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false });
app.use(generalLimiter);

// --------------------------------
// --------------------------------
// -------------AIAC---------------
// ---------- CSRF (Signed Double-Submit Cookie) ----------
// const IS_PROD = process.env.NODE_ENV === 'production';
// const CSRF_COOKIE = '__Host-csrf_secret';
// const CSRF_HEADER = 'X-CSRF-Token';
const IS_PROD = process.env.NODE_ENV === 'production';
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

// In-memory session store (replace with Redis/DB in production)
const sessions = new Map();

// Added: basic expiry cleanup for stale sessions
setInterval(() => {
	const now = Math.floor(Date.now()/1000);
	for (const [sid, s] of sessions) {
		if (s.expires_at && s.expires_at < now - 300) sessions.delete(sid);
	}
}, 60_000).unref();

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
	if (!verifyCsrfToken(req)) return res.status(403).json({ error: 'Invalid CSRF token' });
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

// Sessions & auth helpers
const supaAnon = () => createClient(SUPABASE_URL, SUPABASE_ANON, {
	auth: { persistSession: false, autoRefreshToken: false },
});
const supaWithToken = (access_token) => createClient(SUPABASE_URL, SUPABASE_ANON, {
	global: { headers: { Authorization: `Bearer ${access_token}` } },
	auth: { persistSession: false, autoRefreshToken: false },
});
function setSidCookie(res, sid) {
	res.cookie('sid', sid, {
		httpOnly: true,
		secure: IS_PROD,     // false in dev ;; In dev over http, SameSite=None cookies may be rejected by some browsers
		sameSite: IS_PROD ? 'none' : 'lax', // 'lax' works across localhost ports
		path: '/',
	});
}

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 50 });

app.post('/auth/login', authLimiter, requireCsrf, async (req, res) => {
	const { email, password } = req.body ?? {};
	if (!email || !password) return res.status(400).json({ error: 'email and password required' });

	const { data, error } = await supaAnon().auth.signInWithPassword({ email, password });
	if (error || !data?.session) return res.status(401).json({ error: 'invalid credentials' });

	const { access_token, refresh_token, expires_at } = data.session;
	const sid = b64url(crypto.randomBytes(32));
	sessions.set(sid, { access_token, refresh_token, expires_at });
	setSidCookie(res, sid);
	localLogger('auth-in request successful', {email})
	res.status(204).end();
});

app.post('/auth/logout', authLimiter, requireCsrf, async (req, res) => {
	const sid = req.cookies?.sid;
	const sess = sid ? sessions.get(sid) : null;
	if (sess) {
		await supaWithToken(sess.access_token).auth.signOut();
		sessions.delete(sid);
	}
	// Clear cookie using the same attributes used when setting it
	res.clearCookie('sid', { path: '/', sameSite: IS_PROD ? 'none' : 'lax', secure: IS_PROD, httpOnly: true });
	localLogger('auth-out request successful')
	res.status(204).end();
});

// Refresh access token using stored refresh_token
app.post('/auth/refresh', authLimiter, requireCsrf, async (req, res) => {
	const sid = req.cookies?.sid;
	if (!sid) return res.status(401).json({ error: 'not authenticated' });
	const sess = sessions.get(sid);
	if (!sess) return res.status(401).json({ error: 'not authenticated' });

	const { data, error } = await supaAnon().auth.refreshSession({ refresh_token: sess.refresh_token });
	if (error || !data?.session) {
		sessions.delete(sid);
		// Clear cookie using the same attributes used when setting it
		res.clearCookie('sid', { path: '/', sameSite: IS_PROD ? 'none' : 'lax', secure: IS_PROD, httpOnly: true });
		return res.status(401).json({ error: 'refresh failed' });
	}
	const { access_token, refresh_token, expires_at } = data.session;
	sessions.set(sid, { access_token, refresh_token, expires_at });
	res.status(204).end();
});

// Verify current session (does not leak tokens)
app.get('/auth/session', authLimiter, async (req, res) => {
	const sid = req.cookies?.sid;
	if (!sid) return res.status(401).json({ authenticated: false });
	const sess = sessions.get(sid);
	if (!sess) return res.status(401).json({ authenticated: false });

	// Optionally auto-refresh if near expiry
	const now = Math.floor(Date.now() / 1000);
	if (sess.expires_at && now > (sess.expires_at - 30)) {
		const { data, error } = await supaAnon().auth.refreshSession({ refresh_token: sess.refresh_token });
		if (error || !data?.session) {
			sessions.delete(sid);
			// Clear cookie using the same attributes used when setting it
			res.clearCookie('sid', { path: '/', sameSite: IS_PROD ? 'none' : 'lax', secure: IS_PROD, httpOnly: true });
			return res.status(401).json({ authenticated: false });
		}
		const { access_token, refresh_token, expires_at } = data.session;
		sessions.set(sid, { access_token, refresh_token, expires_at });
	}

	const { data, error } = await supaWithToken(sessions.get(sid).access_token).auth.getUser();
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

app.use((_, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  console.error('[Unhandled error]', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(port, () => {
	console.log(`Starting server on port: ${port}`);
});

server.headersTimeout = 62000;   // 62s
server.keepAliveTimeout = 61000; // 61s
// how long the server keeps the TCP connection idle waiting for the next request before destroying the socket
// For apps behind load balancers (ALB/ELB, GCP, etc.), it’s common to set keepAliveTimeout slightly above the LB’s idle timeout (e.g., 61s for a 60s LB) so the server doesn’t close first, avoiding intermittent 502/ECONNRESET issues.
// Also, make headersTimeout a bit greater than keepAliveTimeout (e.g., 62s vs 61s) so when a client reuses a keep-alive connection, there’s a small grace period to deliver the next request’s headers. Your code currently has headersTimeout (60s) below keepAliveTimeout (61s); flip that to follow the common guidance.
server.requestTimeout = 30000;   // 30s