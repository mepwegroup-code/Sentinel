import type { Request, Response } from "express";
import { createApp } from "../server";

const appPromise = createApp();

export default async function handler(req: Request, res: Response) {
  try {
    const app = await appPromise;
    // Vercel routes all /api/* requests to this handler.
    // Preserve the original API path if the routing layer rewrote the URL.
    const original = req.headers["x-vercel-original-path"];
    if (typeof original === "string" && original.startsWith("/api/")) {
      req.url = original;
    }
    app(req, res);
  } catch (error) {
    console.error("Sentinel API initialization failed", error);
    if (!res.headersSent) res.status(500).json({error:"API initialization failed"});
  }
}
