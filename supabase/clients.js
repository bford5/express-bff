import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
dotenv.config();
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_SAFE_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON) {
    throw new Error('Missing Supabase envs: SUPABASE_URL and ANON/SAFE key are required');
}

export const supaAnon = () =>
    createClient(SUPABASE_URL, SUPABASE_ANON, {
        auth: { persistSession: false, autoRefreshToken: false },
    });

export const supaWithToken = (access_token) =>
    createClient(SUPABASE_URL, SUPABASE_ANON, {
        global: { headers: { Authorization: `Bearer ${access_token}` } },
        auth: { persistSession: false, autoRefreshToken: false },
    });


