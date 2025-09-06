import { createClient } from '@supabase/supabase-js';

export const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY, // SERVICE ROLE — keep on server only
  { auth: { persistSession: false } }
);