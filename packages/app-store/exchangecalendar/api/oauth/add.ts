import type { NextApiRequest, NextApiResponse } from "next";
import { stringify } from "querystring";

import { WEBAPP_URL_FOR_OAUTH } from "@calcom/lib/constants";

import { encodeOAuthState } from "../../../_utils/oauth/encodeOAuthState";

const DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"];

function getEnv(name: string, fallback?: string) {
  const v = process.env[name];
  if (typeof v === "string" && v.length > 0) return v;
  return fallback;
}

async function getDiscovery(authority: string) {
  const wellKnown = authority.replace(/\/$/, "") + "/adfs/.well-known/openid-configuration";
  const resp = await fetch(wellKnown);
  if (!resp.ok) throw new Error(`Failed to load ADFS discovery from ${wellKnown}`);
  return (await resp.json()) as { authorization_endpoint?: string };
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.status(405).json({ message: "Method not allowed" });
    return;
  }

  const clientId = getEnv("EXCHANGE_OAUTH_CLIENT_ID", "");
  if (!clientId) return res.status(400).json({ message: "Exchange OAuth client_id missing." });

  const authority = getEnv("EXCHANGE_OAUTH_AUTHORITY", "");
  if (!authority) return res.status(400).json({ message: "Exchange OAuth authority missing." });

  const ewsUrl = typeof req.query.url === "string" ? req.query.url : undefined;
  if (!ewsUrl) return res.status(400).json({ message: "Missing EWS url" });

  const stateProvided = encodeOAuthState(req);
  const state =
    stateProvided ||
    JSON.stringify({
      fromApp: true,
      onErrorReturnTo: "/apps/installed",
      returnTo: "/apps/installed",
      ewsUrl,
    });

  const discovery = await getDiscovery(authority);
  const authorizationEndpoint =
    discovery.authorization_endpoint || authority.replace(/\/$/, "") + "/adfs/oauth2/authorize";

  const useScopes = DEFAULT_SCOPES;

  const params: Record<string, string> = {
    response_type: "code",
    client_id: clientId,
    redirect_uri: `${WEBAPP_URL_FOR_OAUTH}/api/integrations/exchangecalendar/oauth_callback`,
    scope: useScopes.join(" "),
    state,
  };

  const url = `${authorizationEndpoint}?${stringify(params)}`;
  res.status(200).json({ url });
}
