# Sentinel OS — Vercel deployment

## 1. Deploy from GitHub

1. Merge PR #2 into `main` after passing GitHub Actions.
2. In Vercel: Add New Project → Import `mepwegroup-code/Sentinel` → **Vite**.
3. Build: `npm run build:vercel`; Output: `dist`; Node.js **22** (project setting).
4. Define these **server-side** environment variables under Settings → Environment Variables:

| Variable | Purpose |
| --- | --- |
| `SENTINEL_ADMIN_PASSWORD` | Operator login password (12+ characters; never add to GitHub). |
| `SENTINEL_SESSION_SECRET` | Random key 32+ characters for signing HttpOnly session cookies. |
| `GEMINI_API_KEY` | Optional AI feature key; only on server (no `VITE_` prefix). |

Generate a random session secret locally with `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`.

5. Deploy and check `GET /api/health` and `GET /api/auth/status` (the latter should report `configured:true`).
6. Sign in using **admin** and the password stored in Vercel. Credentials are verified by the server and the signed session is stored in a Secure, HttpOnly, SameSite cookie.
7. Git pushes to the configured production branch will trigger subsequent Vercel deployments automatically.

## 2. Test the source

```bash
npm install
npm run check
npm run build:vercel
```

The CI workflow validates TypeScript and the frontend build. A `package-lock.json` is not yet committed; add it for reproducible installs and switch CI to `npm ci`.

## 3. Operational and security boundaries

- Vercel can host the website and HTTPS API but **cannot connect to a visitor's private LAN**. Keep the RFC1918/SSRF boundary intact.
- Local LAN inspection requires an explicitly authorized agent installed on an on-premises PC. The existing `agent/sentinel-agent.mjs` is only a development prototype.
- **LAN telemetry ingestion on Vercel is disabled** until authenticated, persistent storage is implemented. The API returns `PERSISTENT_LAN_STORAGE_REQUIRED`. In-memory Express Map state is not reliable across serverless instances.
- **Device isolation, bandwidth throttling, Wake-on-LAN, and deep scanning are not implemented on the Vercel backend**. Requests return HTTP 501 instead of falsely reporting completion.
- All API inspection actions require an authenticated operator session. Before scanning any website or IP, confirm permission and target scope.
- DNS rebinding, redirect handling, and worker-level egress restrictions require additional hardening for an Internet-exposed scanner. Treat the current deployment as a **restricted/private preview**, not an unrestricted public pentest service.
- Scan jobs longer than the configured Vercel Function duration require a separate queued worker. Runtime sessions, counters, and caches are not durable.
- Some original global-threat and LAN map values are demonstrations and **must not be treated as real measurements** until backed by a verified feed/agent.

## 4. Troubleshooting

- `/api/health` does not return JSON → check Vercel API rewrite and Function logs.
- `/api/auth/status` reports `configured:false` → set the two authentication environment variables and redeploy.
- HTTP 401 on /api/* → authenticate again; signed session expires after eight hours.
- LAN agent report HTTP 503 → expected until a persistent telemetry ingestion service is configured.
- Missing AI response → check `GEMINI_API_KEY` and model availability.
