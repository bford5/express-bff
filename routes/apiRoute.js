// ---------------
// will safely return a list of all known api routes
// ---------------
// used for crawler function
export const routesMeta = [
	{ route: '/api/api-routes', description: 'Get all api routes' },
];
// ---------------
import express from 'express';

import { getApiRoutesController } from '../controllers/apiRouteController.js';

const router = express.Router();

router.get('/api-routes', getApiRoutesController);

export default router;
