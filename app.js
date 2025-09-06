import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import dotenv from 'dotenv';
// import supabase from './supabase/supabase_server.js';
// ---------------
import apiRoutes from './routes/apiRoute.js';
import postsRoute from './routes/postsRoute.js';
import downloadResumeRoute from './routes/downloadResumeRoute.js';
import { rateLimiter } from './middleware/rateLimiter.js';
// ---------------
dotenv.config();
const port = process.env.PORT;

// ---------------
// ---------------
const app = express();
app.use(bodyParser.json()); // parses application/json

app.use(cors({
	origin: '*', // update this to my client domain
	methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
	allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use((req, res, next) => {
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader(
		'Access-Control-Allow-Methods',
		'GET, POST, PUT, PATCH, DELETE'
	);
	res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
	next();
});

app.use('/api', apiRoutes);
app.use('/api/posts', postsRoute);
app.use('/download/resume', rateLimiter, downloadResumeRoute);

app.get('/', (req, res) => {
	res.send('Hello World!');
});

app.listen(port, () => {
	console.log(`Starting server on port: ${port}`);
});
