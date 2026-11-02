import type { Request, Response } from "express";
import { createApp } from "../server";

const appPromise = createApp();

export default async function handler(req: Request, res: Response) {
  try {
    const app = await appPromise;
    // Vercel routes all /api/* requests to this handler.
    // Preserve the original API path if the routing layer rewrote the URL.
    const requested = new URL(req.url || "/", "http://localhost");
    const apiPath = requested.searchParams.get("sentinelPath");
    const agentPath = requested.searchParams.get("sentinelAgentPath");
    if (apiPath !== null || agentPath !== null) {
      requested.searchParams.delete("sentinelPath");
      requested.searchParams.delete("sentinelAgentPath");
      const suffix = (apiPath ?? agentPath ?? "").replace(/^\\/+/, "");
      req.url = `${apiPath !== null ? "/api/" : "/agent/"}${suffix}${requested.search}`;
    }
    app(req, res);
  } catch (error) {
    console.error("Sentinel API initialization failed", error);
    if (!res.headersSent) res.status(500).json({error:"API initialization failed"});
  }
}
