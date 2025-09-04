import express from 'express';
import bodyParser from 'body-parser';
// import supabase from './supabase/supabase_server.js';
// ---------------
import apiRoutes from './routes/apiRoute.js';
import dotenv from 'dotenv';
dotenv.config();
const port = process.env.PORT;

// ---------------
// ---------------
const app = express();
app.use(bodyParser.json()); // parses application/json

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

app.get('/', (req, res) => {
	res.send('Hello World!');
});

app.listen(port, () => {
	console.log(`Starting server on port: ${port}`);
});
