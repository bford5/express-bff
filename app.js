import express /*{type Application, type Request, type Response, type NextFunction}*/ from 'express';
// import bodyParser from 'body-parser';
import cors/*, { type CorsOptions, type CorsOptionsDelegate }*/ from 'cors';
import dotenv from 'dotenv';
// import supabase from './supabase/supabase_server.js';
// ---------------
import apiRoutes from './routes/apiRoute.js';
import postsRoute from './routes/postsRoute.js';
import downloadResumeRoute from './routes/downloadResumeRoute.js';
import rateLimiter from './middleware/rateLimiter.js';
// ---------------
dotenv.config();
const port = process.env.PORT;

// ---------------
const app = express();
// ---------------
// app.use(bodyParser.json()); // parses application/json
app.use(express.json()); // or express.urlencoded({ extended: true })
// ---------------

const allowlist = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const corsDelegate = (req, cb) => {
	const requested = req.headers['access-control-request-headers'];
	const allowedHeaders =
	  typeof requested === 'string'
		? requested.split(',').map(h => h.trim())
		: ['Content-Type', 'Authorization'];
  
	cb(null, {
	  origin: (origin, done) => done(null, !origin || allowlist.includes(origin)),
	  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
	  credentials: true,
	  maxAge: 600,
	  exposedHeaders: ['Content-Disposition','X-RateLimit-Limit','X-RateLimit-Remaining'],
	  allowedHeaders,
	});
};

// Express helper that safely appends without dupes
app.use((_, res, next) => { res.vary('Origin'); next(); });

// CORS (single source of truth)
app.use(cors(corsDelegate));
// app.options('*', cors(corsDelegate)); // explicit preflight handler

// ---------------
// app.use(cors({
// 	origin: '*', // update this to my client domain
// 	methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
// 	allowedHeaders: ['Content-Type', 'Authorization'],
// }));

// app.use((req, res, next) => {
// 	res.setHeader('Access-Control-Allow-Origin', '*');
// 	res.setHeader(
// 		'Access-Control-Allow-Methods',
// 		'GET, POST, PUT, PATCH, DELETE'
// 	);
// 	res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
// 	next();
// });
// ---------------

// Don't rate-limit preflights (OPTIONS carry no creds)
app.use((req, res, next) => (req.method === 'OPTIONS' ? res.sendStatus(204) : next()));

app.use('/api', apiRoutes);
app.use('/api/posts', postsRoute);
app.use('/download/resume', rateLimiter, downloadResumeRoute);

app.get('/', (_, res) => {
	res.send('Hello World!');
});

app.listen(port, () => {
	console.log(`Starting server on port: ${port}`);
});
