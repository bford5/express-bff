// ---------------
// AIAC
// reads from routes directory and returns a list of all known api routes based on routesMeta
// ---------------

// import supabase from '../supabase/supabase_server.js';
import { readdir } from 'fs/promises';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function getApiRoutesController(req, res) {
	try {
		const routesDir = path.join(__dirname, '../routes');
		const files = (await readdir(routesDir)).filter((f) => f.endsWith('.js'));
		const allRoutesMeta = [];

		await Promise.all(
			files.map(async (fileName) => {
				const filePath = path.join(routesDir, fileName);
				const moduleUrl = pathToFileURL(filePath).href;
				const mod = await import(moduleUrl);
				if (mod.routesMeta && Array.isArray(mod.routesMeta)) {
					allRoutesMeta.push(...mod.routesMeta);
				}
			})
		);

		res.status(200).json({ routes: allRoutesMeta });
	} catch (err) {
		console.error('Error collecting route metadata:', err);
		res.status(500).json({ error: 'Failed to list API routes' });
	}
}
// ---------------
