import type { NextApiRequest, NextApiResponse } from "next";

import { WEBAPP_URL, WEBAPP_URL_FOR_OAUTH } from "@calcom/lib/constants";
import { handleErrorsJson } from "@calcom/lib/errors";
import { symmetricEncrypt } from "@calcom/lib/crypto";
import logger from "@calcom/lib/logger";
import prisma from "@calcom/prisma";

import getInstalledAppPath from "../../../_utils/getInstalledAppPath";
import { decodeOAuthState } from "../../../_utils/oauth/decodeOAuthState";
import { ExchangeAuthentication } from "../../enums";
import { CalendarService } from "../../lib";

function getEnv(name: string, fallback?: string) {
  const v = process.env[name];
  if (typeof v === "string" && v.length > 0) return v;
  return fallback;
}

async function getDiscovery(authority: string) {
  const wellKnown = authority.replace(/\/$/, "") + "/adfs/.well-known/openid-configuration";
  const resp = await fetch(wellKnown);
  if (!resp.ok) throw new Error(`Failed to load ADFS discovery from ${wellKnown}`);
  return (await resp.json()) as { token_endpoint?: string };
}

const toUrlEncoded = (payload: Record<string, string>) =>
  Object.keys(payload)
    .map((key) => `${key}=${encodeURIComponent(payload[key])}`)
    .join("&");

type ExchangeTokenResponse = {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number | string;
  token_type?: string;
  scope?: string;
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const state = decodeOAuthState(req) as
    | (ReturnType<typeof decodeOAuthState> & { ewsUrl?: string })
    | undefined;

  const code = typeof req.query.code === "string" ? req.query.code : undefined;
  if (!code) {
    res.redirect(`${WEBAPP_URL}/apps/installed`);
    return;
  }

  // Env-driven client credentials
  const clientId = getEnv("EXCHANGE_OAUTH_CLIENT_ID", "");
  const clientSecret = getEnv("EXCHANGE_OAUTH_CLIENT_SECRET", "");
  if (!clientId || !clientSecret)
    return res.status(400).json({ message: "Exchange OAuth client credentials missing." });

  const authority = getEnv("EXCHANGE_OAUTH_AUTHORITY", "");
  if (!authority) return res.status(400).json({ message: "Exchange OAuth authority missing." });

  const discovery = await getDiscovery(authority);
  const tokenEndpoint = discovery.token_endpoint || authority.replace(/\/$/, "") + "/adfs/oauth2/token";

  const body: Record<string, string> = {
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "authorization_code",
    code,
    redirect_uri: `${WEBAPP_URL_FOR_OAUTH}/api/integrations/exchangecalendar/oauth_callback`,
  };

  const response = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
    body: toUrlEncoded(body),
  });

  const tokenResponse = await handleErrorsJson<ExchangeTokenResponse>(response).catch(async (e) => {
    const text = await response.text().catch(() => "");
    logger.error("Exchange OAuth token error", { status: response.status, text, err: String(e) });
    throw e;
  });

  const accessToken: string | undefined = tokenResponse.access_token;
  const refreshToken: string | undefined = tokenResponse.refresh_token;
  const expiresInSec: number | undefined =
    tokenResponse.expires_in !== undefined ? Number(tokenResponse.expires_in) : undefined;
  const expiry_date = expiresInSec ? Math.round(+new Date() / 1000 + expiresInSec) : undefined;

  const ewsUrl = state?.ewsUrl;
  if (!ewsUrl) {
    res.redirect(`${WEBAPP_URL}/apps/installed?error=missing_ews_url`);
    return;
  }

  const key = {
    authenticationMethod: ExchangeAuthentication.MODERN,
    ewsUrl,
    token: {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: expiry_date, // keep same semantics used elsewhere (seconds since epoch)
      token_type: tokenResponse.token_type || "Bearer",
      scope: tokenResponse.scope,
    },
  };

  const session = req.session;
  const userId = session?.user?.id ?? null;
  try {
    const encrypted = symmetricEncrypt(JSON.stringify(key), process.env.CALENDSO_ENCRYPTION_KEY || "");
    const data = {
      type: "exchange_calendar",
      key: encrypted,
      userId,
      teamId: null as number | null,
      appId: "exchange",
      invalid: false,
      delegationCredentialId: null as string | null,
    };

    // Validate by listing calendars once
    if (userId) {
      const service = new CalendarService({ id: 0, user: { email: session?.user?.email || "" }, ...data });
      await service.listCalendars();
    }

    await prisma.credential.create({ data });
  } catch (e) {
    logger.error("Exchange OAuth callback error", { err: String(e) });
    res.redirect(`${WEBAPP_URL}/apps/installed?error=exchange_oauth_failed`);
    return;
  }

  res.redirect(getInstalledAppPath({ variant: "calendar", slug: "exchange" }));
}
