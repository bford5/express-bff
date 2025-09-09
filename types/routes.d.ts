declare module './routes/*.js' {
	import { Router } from 'express';
	const router: Router;
	export default router;
  }

declare module './middleware/*.js' {
	import { RequestHandler } from 'express';
	const rateLimiter: RequestHandler;
	export default rateLimiter;
  }


declare module './routes/apiRoute.js' {
	import { Router } from 'express';
	const router: Router;
	export default router;
  }
declare module './routes/postsRoute.js' {
	import { Router } from 'express';
	const router: Router;
	export default router;
  }
declare module './routes/downloadResumeRoute.js' {
	import { Router } from 'express';
	const router: Router;
	export default router;
  }