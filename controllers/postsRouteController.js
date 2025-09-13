import supabase from '../supabase/supabase_server.js';
import { localLogger } from '../helpers/localLogger.js';

export const getPostsRouteController = async (_, response) => {
	try {
		const { data, error, status } = await supabase
			.from('posts')
			.select('*')
			.eq('isActive', true);
		if (error) {
			localLogger('error getting posts', error);
			return response.status(status || 500).json({
				error: { message: 'Failed to fetch posts' }, // safe, client-facing
			});
		}
		localLogger('POSTS data from supabase', data);
		return response.status(200).send(data);
		// return response.status(200).json({
		// 	posts: data,
		// });
	} catch (error) {
		// return response.send({ error });
		return response.status(500).json({ error: { message: 'Unexpected error' } });
	}
};

// ---------------
// optional cache route controller for practice and testing
// ---------------
let postsCache = { data: null, expiresAt: 0 };
const TTL_MS = 60 * 1000; // 1 minute

export const getPostsRouteControllerWithCache = async (_, response) => {
	try {
		// serve from cache if fresh
		if (postsCache.data && Date.now() < postsCache.expiresAt) {
			localLogger('serving from CACHE');
			return response
				.status(200)
				.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300')
				.json(postsCache.data);
				// .send(postsCache.data);
		}

		// fetch fresh
		const { data, error, status } = await supabase
			.from('posts')
			.select('*')
			.eq('isActive', true);
		localLogger('fetching posts FRESH', data);

		if (error) {
			localLogger('error fetching posts', error);
			return response.status(status || 500).json({
				error: { message: 'Failed to fetch posts' },
			});
		}

		// update cache and return
		postsCache = { data, expiresAt: Date.now() + TTL_MS };

		return response
			.status(200)
			.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300')
			.json(data);
			// .send(data);
	} catch (error) {
		return response.status(500).json({ error: { message: 'Unexpected error' } });
	}
};