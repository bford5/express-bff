# Node API for Personal Site

Express API that authenticates with Supabase and issues a secure httpOnly session cookie ("sid") for use by a separate front-end.

Notating summaries & documentation in-line for reference where applicable

Intentionally not using TS yet in this version, began setup but paused

## Required environment

Create a `.env` file in this directory:

```
PORT=3001
NODE_ENV=development
SUPABASE_URL=your_supabase_url
SUPABASE_ANON_KEY=your_supabase_anon_or_safe_key
# Comma-separated list of allowed web origins (scheme+host+port)
ALLOWED_ORIGINS=http://localhost:4321,http://127.0.0.1:4321
```

Notes:
- In production, set `NODE_ENV=production`. Cookies will be sent with `SameSite=None; Secure`.
- Include your deployed front-end origin in `ALLOWED_ORIGINS`.

## Install & run

```
npm install
npm run start
# or for TS dev workflow
npm run dev
```

## Auth endpoints

All state-changing requests require a CSRF token via `X-CSRF-Token` header. Obtain it first from `/auth/csrf`.

- `GET /auth/csrf` → `{ csrfToken }` and sets a CSRF secret cookie
- `POST /auth/login` `{ email, password }` + `X-CSRF-Token` → sets `sid` cookie, 204
- `POST /auth/logout` + `X-CSRF-Token` → clears `sid`, 204
- `POST /auth/refresh` + `X-CSRF-Token` → refreshes session, 204
- `GET /auth/session` → `{ authenticated: boolean, user?: {...} }`

Example (dev) login flow:

```
# 1) Get CSRF
curl -i -c cookies.txt http://localhost:3001/auth/csrf
# 2) Login
curl -i -b cookies.txt -c cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <paste csrfToken>" \
  -d '{"email":"user@example.com","password":"secret"}' \
  http://localhost:3001/auth/login
# 3) Check session
curl -i -b cookies.txt http://localhost:3001/auth/session
```

## CORS

CORS is enabled with credentials. Requests from origins not in `ALLOWED_ORIGINS` will be rejected.


