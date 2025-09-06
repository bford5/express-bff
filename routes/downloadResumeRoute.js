// ---------------
// used for crawler function
export const routesMeta = [
	{ route: '/download/resume', description: 'download my resume' },
];
// ---------------
import { Router } from 'express';
import { supabaseAdmin } from '../supabase/supabase_admin.js';
import { Readable } from 'node:stream';
import { localLogger } from '../helpers/localLogger.js';

const router = Router();

// Optional: centralize these so you don’t trust client input for paths
const BUCKET = 'myResumeBucket';
const OBJECT_PATH = 'resume/brandon_ford_resume.pdf';
const DOWNLOAD_NAME = 'Brandon-Ford-Resume.pdf';

router.get('/', async (req, res) => {
  try {
    // (Optional) authorize the user here if needed (req.user, cookie, etc.)

    const { data, error } = await supabaseAdmin
      .storage
      .from(BUCKET)
      .download(OBJECT_PATH);
	
	  if (data) {
		// console.log('--------------------------------');
		// console.log(new Date().toISOString());
		// console.log('file from supabase acquired');
		// console.log('--------------------------------');
		localLogger('file from supabase acquired');
	  }

    if (error || !data) {
      console.error('[Supabase download error]', error);
      return res.status(502).json({ message: 'Failed to fetch file' });
    }

    // data is a Blob (Node 18+ supports Web Streams/Blob)
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${DOWNLOAD_NAME}"`);
    res.setHeader('Cache-Control', 'private, no-store'); // adjust if you want caching
    if (typeof data.size === 'number') {
      res.setHeader('Content-Length', String(data.size));
    }

    if (typeof data.stream === 'function') {
      // Stream without buffering entire file in memory
      const nodeStream = Readable.fromWeb(data.stream());
      return nodeStream.pipe(res);
    }

    // Fallback: buffer (only if stream() unavailable)
    const buf = Buffer.from(await data.arrayBuffer());
    return res.end(buf);
  } catch (e) {
    console.error('[Download handler error]', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

export default router;