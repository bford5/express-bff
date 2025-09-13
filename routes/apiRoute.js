// ---------------
// will safely return a list of all known api routes
// ---------------
// used for crawler function
export const routesMeta = [
	{ route: '/api/api-routes', description: 'Get all api routes' },
];
// ---------------
import express from 'express';
import {rateLimit} from 'express-rate-limit';

import { getApiRoutesController } from '../controllers/apiRouteController.js';

const router = express.Router();
const routesRateLimiter = rateLimit({ windowMs: 60 * 1000, limit: 25 });

router.get('/api-routes', routesRateLimiter, getApiRoutesController);

export default router;
