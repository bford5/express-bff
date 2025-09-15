// Hardened session store using node-redis + in-memory fallback.
// - Idle TTL + touch() for rolling sessions
// - Optional absolute lifetime cap (__abs)
// - Local in-memory fallback when no redis env's are provided
// - Graceful shutdown
// - TLS via env-provided cert paths (works with K8s/containers secrets)
// References:
// - Redis Node client: https://www.npmjs.com/package/redis
// - Node crash course: https://redis.io/learn/develop/node/node-crash-course
// - OWASP Session Mgmt: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html


import { createClient } from 'redis';
import { localLogger } from './localLogger.js';
// import fs from 'fs';

const redisUrl = process.env.REDIS_HOST && process.env.REDIS_PORT ? `${process.env.REDIS_HOST}:${process.env.REDIS_PORT}` : null;
let redis = null;

function buildRedisClient() {
	// const socket = {};
	// const wantsTls = redisUrl.startsWith('rediss://') || process.env.REDIS_ENABLE_TLS === '1';
	// if (wantsTls) {
	// 	// Node TLS options (buffers/strings), paths provided via env vars
	// 	const trim = (v) => (typeof v === 'string' ? v.trim() : v);
	// 	if (process.env.REDIS_TLS_CA) socket.ca = fs.readFileSync(trim(process.env.REDIS_TLS_CA));
	// 	if (process.env.REDIS_TLS_CERT) socket.cert = fs.readFileSync(trim(process.env.REDIS_TLS_CERT));
	// 	if (process.env.REDIS_TLS_KEY) socket.key = fs.readFileSync(trim(process.env.REDIS_TLS_KEY));
	// 	if (process.env.REDIS_TLS_REJECT_UNAUTHORIZED === '0') socket.rejectUnauthorized = false;
	// 	socket.tls = true;
	// }
	const socket = {host: process.env.REDIS_HOST, port: process.env.REDIS_PORT};
	const clientObject = {
		username: process.env.REDIS_USERNAME,
		password: process.env.REDIS_PASSWORD,
		socket: socket
	}
	// return createClient({ url: redisUrl, socket });
	return createClient(clientObject)
}


if (redisUrl) {
	redis = buildRedisClient();
	redis.on('error', (e) => console.log('[Redis error]', e));
	redis.on('connect', () => console.log('[Redis] connected'));
	// Eagerly connect at startup
	await redis.connect().catch((e) => console.log('[Redis connect error]', e));
}

const PREFIX = 'sess:';
const key = (sid) => `${PREFIX}${sid}`;
const now = () => Date.now();

const mem = new Map(); // sid -> { value, expMs }

// Background cleanup to prevent bloat in memory fallback
setInterval(() => {
	const t = now();
	for (const [sid, entry] of mem) {
		if (entry.expMs && entry.expMs <= t) mem.delete(sid);
	}
}, 60_000).unref();

// Clamp idle TTL to sane bounds: 60s..7d
const clampTtl = (ttlSec) => {
	const s = Math.floor(Number(ttlSec) || 0) || 60;
	return Math.min(60 * 60 * 24 * 7, Math.max(60, s));
};

export const redisSessionStore = {
	async get(sid) {
		if (redis) {
			try {
				const raw = await redis.get(key(sid));
				if (!raw) return null;
				const obj = JSON.parse(raw);
				if (obj && obj.__abs && obj.__abs <= now()) {
					await redis.del(key(sid)).catch(() => {});
					return null;
				}
				return obj;
			} catch {
				await redis.del(key(sid)).catch(() => {});
				return null;
			}
		}
		const entry = mem.get(sid);
		if (!entry) return null;
		if (entry.expMs && entry.expMs <= now()) {
			mem.delete(sid);
			return null;
		}
		return entry.value;
	},

	// ttlSec: idle timeout; absoluteSec: optional hard cap
	async set(sid, value, ttlSec, absoluteSec) {
		const ttl = clampTtl(ttlSec);
		const payload = absoluteSec
			? { ...value, __abs: now() + Math.floor(absoluteSec) * 1000 }
			: value;

		if (redis) {
			await redis.set(key(sid), JSON.stringify(payload), { EX: ttl });
			localLogger('sid set in redis session store')
			return 'OK';
		}
		mem.set(sid, { value: payload, expMs: now() + ttl * 1000 });
		return 'OK';
	},

	// Extend idle TTL without rewriting the value
	async touch(sid, ttlSec) {
		const ttl = clampTtl(ttlSec);
		if (redis) return redis.expire(key(sid), ttl);
		const entry = mem.get(sid);
		if (!entry) return 0;
		entry.expMs = now() + ttl * 1000;
		return 1;
	},

	async del(sid) {
		if (redis) return redis.del(key(sid));
		return mem.delete(sid);
	},

	async close() {
		if (redis) await redis.close();
	},
};