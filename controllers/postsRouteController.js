import supabase from '../supabase/supabase_server.js';

export const getPostsRouteController = async (_, response) => {
	try {
		const { data, error } = await supabase.from('posts').select();
		console.log(data);
		return response.send(data);
	} catch (error) {
		return response.send({ error });
	}
};
