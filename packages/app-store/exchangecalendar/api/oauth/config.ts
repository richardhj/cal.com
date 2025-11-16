import type { NextApiRequest, NextApiResponse } from "next";

function isForcePasswordless() {
  const v = String(process.env.EXCHANGE_FORCE_PASSWORDLESS).toLowerCase();
  return v === "1" || v === "true";
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // Simple config endpoint to let the client know if OAuth is enabled via env
  const enabled = Boolean(process.env.EXCHANGE_OAUTH_AUTHORITY);
  const forcePasswordless = isForcePasswordless();
  res.status(200).json({ enabled, forcePasswordless });
}
