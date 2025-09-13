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

let routesCache = { data: null, expiresAt: 0 };
const TTL_MS = 5 * 60 * 1000; // 5 minutes

export async function getApiRoutesController(req, res) {
	try {
		// serve from cache if fresh
		if (routesCache.data && Date.now() < routesCache.expiresAt) {
			return res.status(200).json(routesCache.data);
		}

		// fetch fresh
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
		
		routesCache = {data: allRoutesMeta, expiresAt: Date.now() + TTL_MS};

		res.status(200).json({ routes: allRoutesMeta });
	} catch (err) {
		console.error('Error collecting route metadata:', err);
		res.status(500).json({ error: 'Failed to list API routes' });
	}
}
// ---------------
