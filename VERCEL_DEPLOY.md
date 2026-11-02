# Sentinel OS — Vercel deployment

1. Import `mepwegroup-code/Sentinel` into Vercel and set the framework preset to **Vite**.
2. Build command: `npm run build:vercel`; output directory: `dist`.
3. Configure `GEMINI_API_KEY` only in Vercel Environment Variables; **do not** expose it with a `VITE_` prefix.
4. Use `/api/health` to check the backend after deploy.
5. Connect the production branch for automatic deployment on GitHub pushes.
6. The web frontend and Express API can run on Vercel, but localhost/LAN scanning **cannot run from Vercel's cloud runtime**. Use a locally installed, authenticated agent on your own network. Do not remove SSRF protections to permit private IP scanning from public endpoints.
7. API requests can exceed serverless timeouts; long running scans should be queued to a dedicated backend/worker. In-memory state and rate limiting are not shared across serverless instances.
8. LAN device topology and threats must be labeled as demonstrations unless supplied by a real, authenticated local agent. Review /api/internal-network and /api/global-threats for simulated records before production use.
9. Review target authorization, request authentication, rate limits, and SSRF protection before exposing scanning actions to the public Internet.

To test locally:
```bash
npm ci
npm run lint
npm run build:vercel
```
