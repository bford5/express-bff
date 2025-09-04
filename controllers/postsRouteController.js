import supabase from '../supabase/supabase_server.js';

export const getPostsRouteController = async (_, response) => {
	try {
		const { data, error } = await supabase.from('posts').select('*');
		if (error) {
			console.log('--------------------------------');
			console.log('error getting posts');
			console.log(error);
			console.log('--------------------------------');
			return response.send({ error });
		}
		console.log('--------------------------------');
		console.log('POSTS data from supabase');
		console.log(data);
		console.log('--------------------------------');
		return response.send(data);
	} catch (error) {
		return response.send({ error });
	}
};
