# Sentinel OS — Coolify / Docker deployment

Sentinel runs as **one long-lived Node.js 22 service**: Express serves `/api/*` and the compiled Vite/React SPA from `dist/`. Do not use the former Vercel build strategy.

## Deploy from GitHub to Coolify

1. Open Coolify → your Project / Environment → **+ New → Application** → Git repository. Connect `https://github.com/mepwegroup-code/Sentinel` using a GitHub App for automatic deployment (or use the public repo URL and configure webhooks).
2. Select **Dockerfile** build pack/strategy, branch `main`, Base Directory `/`, Dockerfile Location `/Dockerfile`.
3. Set **Ports Exposes** to `3000` and assign your own HTTPS domain. Let the Coolify proxy terminate HTTPS; the container listens on `0.0.0.0:3000`.
4. Coolify → Environment Variables (runtime secrets, NOT Docker build arguments):
   - `NODE_ENV=production`
   - `PORT=3000`
   - `SENTINEL_ADMIN_PASSWORD=<unique password, min 12 chars>`
   - `SENTINEL_SESSION_SECRET=<random secret, min 32 chars>`
   - `SENTINEL_AGENT_TOKEN=<another random token, min 32 chars>`
   - `GEMINI_API_KEY=<optional AI API key>`
   - `SENTINEL_DATA_DIR=/app/data`
5. In **Persistent Storage**, add a volume mounted to **`/app/data`**. The last authenticated LAN Agent report is stored as `/app/data/lan-report.json`; without a volume, the report will be lost when the container is replaced. Only one running instance should write this file.
6. **Deploy**. The Dockerfile builds the frontend and server, then runs `node dist/server.cjs`.
7. Verify:
   - `GET https://YOUR-DOMAIN/api/health` → `{"status":"ok", ...}`
   - `GET https://YOUR-DOMAIN/api/auth/status` → `{"configured":true,"authenticated":false}` before login
   - Open the website and log in as `admin` with `SENTINEL_ADMIN_PASSWORD`.
8. Enable **Auto Deploy** for the GitHub source/branch in Coolify. Confirm a subsequent push triggers a rebuild, then review Deployment Logs.

The image itself defines `HEALTHCHECK` for `http://127.0.0.1:3000/api/health`. Don't configure a conflicting Coolify-managed health check.

To generate strong secrets on your own computer:
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

## Send LAN sensor data securely

The LAN Agent scans **your explicitly authorized local network from an on-premises PC**; the cloud-hosted Coolify server cannot directly inspect a remote visitor's private LAN.

1. Download `https://YOUR-DOMAIN/agent/sentinel-agent.mjs` and inspect it before running.
2. Install Node.js 22 on the authorized LAN PC.
3. Set the identical `SENTINEL_AGENT_TOKEN` securely in the agent process environment. Never put it in frontend code or repository.
4. On your own LAN PC run:
   ```bash
   node sentinel-agent.mjs --server https://YOUR-DOMAIN --token my-private-session
   ```
5. Open the Sentinel LAN module after the report is uploaded. The backend caches the latest agent report and persists a 24-hour snapshot under `/app/data`.

Example environment variable for Windows PowerShell (replace with your real token):
```powershell
$env:SENTINEL_AGENT_TOKEN = "REPLACE_WITH_32_PLUS_CHAR_RANDOM_TOKEN"
node .\sentinel-agent.mjs --server https://YOUR-DOMAIN --token my-private-session
```

## Local verification

```bash
npm install
npm run check
npm run build
docker build -t sentinel:coolify .
docker run --rm -p 3000:3000 -e NODE_ENV=production \
  -e SENTINEL_ADMIN_PASSWORD=REPLACE_WITH_LONG_PASSWORD \
  -e SENTINEL_SESSION_SECRET=REPLACE_WITH_32_PLUS_CHAR_RANDOM_SECRET \
  sentinel:coolify
```

## Important security boundaries

- Keep the website behind authentication and restrict access to authorized users and test targets. The app's current scanner is **not yet a fully hardened public pentest platform**. SSRF, DNS rebind, redirect, and egress-policy controls require further review.
- Agent report authentication is separate from the browser's signed session. Never send the agent token in URL query strings.
- "Isolate", "throttle", "Wake-on-LAN" and "deep scan" APIs intentionally respond HTTP 501 until a real network-device integration is implemented.
- Threat-map/demo values in the original project are not proof of a real attack. Review labels before showing results as measured findings.
- The JSON snapshot is suitable for a **single-instance private deployment**, not a replicated production cluster. For multi-instance deployments, use a shared database and proper session ownership.
- Coolify's server hosting, firewall, backups, DNS, SSL, and secret rotation remain the operator's responsibility.
