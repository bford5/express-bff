import {rateLimit, ipKeyGenerator} from 'express-rate-limit';

const rateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,      // 10 minutes window
  max: 5,                        // 5 downloads per window
  standardHeaders: true,         // adds RateLimit-* headers
  legacyHeaders: false,
  message: { message: 'Too many downloads, try again later.' },
  keyGenerator: (req) => req.user?.id ?? ipKeyGenerator(req.ip), // prefer user id if you have auth
});

export default rateLimiter;