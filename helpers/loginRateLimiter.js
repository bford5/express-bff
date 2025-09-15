// Redis-backed login rate limiters using node-rate-limiter-flexible
// Docs: https://github.com/animir/node-rate-limiter-flexible/wiki/Overall-example#login-endpoint-protection

import { RateLimiterRedis } from 'rate-limiter-flexible';
import { createClient } from 'redis';


const socket = {
	host: process.env.REDIS_HOST,
	port: process.env.REDIS_PORT,
	reconnectStrategy: (retries) => Math.min(retries * 50, 500)
}
const clientObject = {
	username: process.env.REDIS_USERNAME,
	password: process.env.REDIS_PASSWORD,
	socket: socket
}

// Reuse existing Redis envs if present; disable offline queue to fail fast
// const redis = createClient({
// 	url: (process.env.REDIS_HOST && process.env.REDIS_PORT)
// 		\? `redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`
// 		: process.env.REDIS_URL,
// 	socket: {
// 		reconnectStrategy(retries) {
// 			return Math.min(retries * 50, 500);
// 		},
// 	},
// });
const redis = createClient(clientObject);

redis.on('error', (e) => console.warn('[rate-limit redis error]', e?.message || e));

let connected = false;
async function ensureRedis() {
	if (!connected) {
		try { await redis.connect(); connected = true; } catch (e) { /* fail fast usage will throw later */ }
	}
}

const maxWrongAttemptsByIPperDay = Number(process.env.RLF_MAX_FAILS_PER_IP_PER_DAY || 100);
const maxConsecutiveFailsByUsernameAndIP = Number(process.env.RLF_MAX_CONSEC_FAILS_USERNAME_IP || 10);

export const limiterSlowBruteByIP = new RateLimiterRedis({
	storeClient: redis,
	keyPrefix: 'login_fail_ip_per_day',
	points: maxWrongAttemptsByIPperDay,
	duration: 60 * 60 * 24, // 1 day
	blockDuration: 60 * 60 * 24, // block for 1 day
});

export const limiterConsecutiveFailsByUsernameAndIP = new RateLimiterRedis({
	storeClient: redis,
	keyPrefix: 'login_fail_consecutive_username_and_ip',
	points: maxConsecutiveFailsByUsernameAndIP,
	duration: 60 * 60 * 24 * 90, // track 90d
	blockDuration: 60 * 60, // 1h block
});

export function getUsernameIPkey(email, ip) {
	return `${(email || '').toLowerCase()}_${ip}`;
}

export async function initLoginRateLimiter() {
	await ensureRedis();
}


