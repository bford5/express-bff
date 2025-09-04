// ---------------
// will safely return a list of all known api routes
// ---------------
// used for crawler function
export const routesMeta = [
	{ route: '/api/posts', description: 'Get all posts' },
];
// ---------------
import express from 'express';

import { getPostsRouteController } from '../controllers/postsRouteController.js';

const router = express.Router();

router.get('/posts', getPostsRouteController);

export default router;
