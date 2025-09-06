import supabase from '../supabase/supabase_server.js';

export const getPostsRouteController = async (_, response) => {
	try {
		const { data, error, status } = await supabase
			.from('posts')
			.select('*')
			.eq('isActive', true);
		if (error) {
			console.log('--------------------------------');
			console.log(new Date().toISOString());
			console.log('error getting posts');
			console.log(error);
			console.log('--------------------------------');
			return response.status(status || 500).json({
				error: { message: 'Failed to fetch posts' }, // safe, client-facing
			});
		}
		console.log('--------------------------------');
		console.log(new Date().toISOString());
		console.log('POSTS data from supabase');
		console.log(data);
		console.log('--------------------------------');
		return response.status(200).send(data);
		// return response.status(200).json({
		// 	posts: data,
		// });
	} catch (error) {
		return response.send({ error });
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
			console.log('--------------------------------');
			console.log(new Date().toISOString());
			console.log('serving from CACHE');
			console.log('--------------------------------');
			return response
				.status(200)
				.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300')
				.send(postsCache.data);
		}

		// fetch fresh
		const { data, error, status } = await supabase
			.from('posts')
			.select('*')
			.eq('isActive', true);
		console.log('--------------------------------');
		console.log(new Date().toISOString());
		console.log('fetching posts FRESH');
		console.log(data);
		console.log('--------------------------------');

		if (error) {
			console.log('--------------------------------');
			console.log(new Date().toISOString());
			console.log('error fetching posts');
			console.log(error);
			console.log('--------------------------------');
			return response.status(status || 500).json({
				error: { message: 'Failed to fetch posts' },
			});
		}

		// update cache and return
		postsCache = { data, expiresAt: Date.now() + TTL_MS };

		return response
			.status(200)
			.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300')
			.send(data);
	} catch (error) {
		return response.status(500).json({ error: { message: 'Unexpected error' } });
	}
};