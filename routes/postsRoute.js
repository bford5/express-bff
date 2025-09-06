// ---------------
// will safely return a list of all known api routes
// ---------------
// used for crawler function
export const routesMeta = [
	{ route: '/api/posts', description: 'Get all posts' },
];
// ---------------
import express from 'express';

import { getPostsRouteController, getPostsRouteControllerWithCache } from '../controllers/postsRouteController.js';

const router = express.Router();

// route defined in app.js so the path param here is just /
// the route kv on line 6 is what is used in app.js
// when calling this route handler in app.js
// router.get('/', getPostsRouteController);
router.get('/', getPostsRouteControllerWithCache);

export default router;
