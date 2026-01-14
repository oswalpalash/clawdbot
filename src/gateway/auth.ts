import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type {
  GatewayAuthConfig,
  GatewayTailscaleMode,
} from "../config/config.js";
export type ResolvedGatewayAuthMode = "none" | "token" | "password";

export type ResolvedGatewayAuth = {
  mode: ResolvedGatewayAuthMode;
  token?: string;
  password?: string;
  allowTailscale: boolean;
};

export type GatewayAuthResult = {
  ok: boolean;
  method?: "none" | "token" | "password" | "tailscale";
  user?: string;
  reason?: string;
};

type ConnectAuth = {
  token?: string;
  password?: string;
};

type TailscaleUser = {
  login: string;
  name: string;
  profilePic?: string;
};

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function isLoopbackAddress(ip: string | undefined): boolean {
  if (!ip) return false;
  if (ip === "127.0.0.1") return true;
  if (ip.startsWith("127.")) return true;
  if (ip === "::1") return true;
  if (ip.startsWith("::ffff:127.")) return true;
  return false;
}

function normalizeIp(ip: string): string {
  if (ip.startsWith("::ffff:")) return ip.slice("::ffff:".length);
  return ip;
}

function isTailscaleAddress(ip: string | undefined): boolean {
  if (!ip) return false;
  const normalized = normalizeIp(ip.trim().toLowerCase());
  if (!normalized) return false;
  if (normalized.includes(":")) {
    // Tailscale IPv6 ULA prefix: fd7a:115c:a1e0::/48
    return normalized.startsWith("fd7a:115c:a1e0:");
  }

  const parts = normalized.split(".");
  if (parts.length !== 4) return false;
  const octets = parts.map((part) => Number.parseInt(part, 10));
  if (octets.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return false;

  // Tailscale IPv4 range: 100.64.0.0/10
  const [a, b] = octets;
  return a === 100 && b >= 64 && b <= 127;
}

function getHostName(hostHeader: string): string {
  const host = hostHeader.trim().toLowerCase();
  if (!host) return "";
  if (host.startsWith("[")) {
    const end = host.indexOf("]");
    if (end !== -1) return host.slice(1, end);
  }
  const [name] = host.split(":");
  return name ?? "";
}

function isLocalDirectRequest(req?: IncomingMessage): boolean {
  if (!req) return false;
  const clientIp = req.socket?.remoteAddress ?? "";
  const clientIsLoopback = isLoopbackAddress(clientIp);
  const clientIsTailscale = isTailscaleAddress(clientIp);

  const host = getHostName(req.headers?.host ?? "");
  const hostIsLocal =
    host === "localhost" || host === "127.0.0.1" || host === "::1";
  const hostIsTailscale = host.endsWith(".ts.net") || isTailscaleAddress(host);

  const hasForwarded = Boolean(
    req.headers?.["x-forwarded-for"] ||
      req.headers?.["x-real-ip"] ||
      req.headers?.["x-forwarded-host"],
  );

  const isLocalHostMatch =
    (clientIsLoopback && hostIsLocal) ||
    (clientIsLoopback && hostIsTailscale) ||
    (clientIsTailscale && hostIsTailscale);

  return isLocalHostMatch && !hasForwarded;
}

function getTailscaleUser(req?: IncomingMessage): TailscaleUser | null {
  if (!req) return null;
  const login = req.headers["tailscale-user-login"];
  if (typeof login !== "string" || !login.trim()) return null;
  const nameRaw = req.headers["tailscale-user-name"];
  const profilePic = req.headers["tailscale-user-profile-pic"];
  const name =
    typeof nameRaw === "string" && nameRaw.trim()
      ? nameRaw.trim()
      : login.trim();
  return {
    login: login.trim(),
    name,
    profilePic:
      typeof profilePic === "string" && profilePic.trim()
        ? profilePic.trim()
        : undefined,
  };
}

function hasTailscaleProxyHeaders(req?: IncomingMessage): boolean {
  if (!req) return false;
  return Boolean(
    req.headers["x-forwarded-for"] &&
      req.headers["x-forwarded-proto"] &&
      req.headers["x-forwarded-host"],
  );
}

function isTailscaleProxyRequest(req?: IncomingMessage): boolean {
  if (!req) return false;
  return (
    isLoopbackAddress(req.socket?.remoteAddress) &&
    hasTailscaleProxyHeaders(req)
  );
}

export function resolveGatewayAuth(params: {
  authConfig?: GatewayAuthConfig | null;
  env?: NodeJS.ProcessEnv;
  tailscaleMode?: GatewayTailscaleMode;
}): ResolvedGatewayAuth {
  const authConfig = params.authConfig ?? {};
  const env = params.env ?? process.env;
  const token = authConfig.token ?? env.CLAWDBOT_GATEWAY_TOKEN ?? undefined;
  const password =
    authConfig.password ?? env.CLAWDBOT_GATEWAY_PASSWORD ?? undefined;
  const mode: ResolvedGatewayAuth["mode"] =
    authConfig.mode ?? (password ? "password" : token ? "token" : "none");
  const allowTailscale =
    authConfig.allowTailscale ??
    (params.tailscaleMode === "serve" && mode !== "password");
  return {
    mode,
    token,
    password,
    allowTailscale,
  };
}

export function assertGatewayAuthConfigured(auth: ResolvedGatewayAuth): void {
  if (auth.mode === "token" && !auth.token) {
    throw new Error(
      "gateway auth mode is token, but no token was configured (set gateway.auth.token or CLAWDBOT_GATEWAY_TOKEN)",
    );
  }
  if (auth.mode === "password" && !auth.password) {
    throw new Error(
      "gateway auth mode is password, but no password was configured",
    );
  }
}

export async function authorizeGatewayConnect(params: {
  auth: ResolvedGatewayAuth;
  connectAuth?: ConnectAuth | null;
  req?: IncomingMessage;
}): Promise<GatewayAuthResult> {
  const { auth, connectAuth, req } = params;
  const localDirect = isLocalDirectRequest(req);

  if (auth.allowTailscale && !localDirect) {
    const tailscaleUser = getTailscaleUser(req);
    const tailscaleProxy = isTailscaleProxyRequest(req);

    if (tailscaleUser && tailscaleProxy) {
      return {
        ok: true,
        method: "tailscale",
        user: tailscaleUser.login,
      };
    }

    if (auth.mode === "none") {
      if (!tailscaleUser) {
        return { ok: false, reason: "tailscale_user_missing" };
      }
      if (!tailscaleProxy) {
        return { ok: false, reason: "tailscale_proxy_missing" };
      }
    }
  }

  if (auth.mode === "none") {
    return { ok: true, method: "none" };
  }

  if (auth.mode === "token") {
    if (!auth.token) {
      return { ok: false, reason: "token_missing_config" };
    }
    if (!connectAuth?.token) {
      return { ok: false, reason: "token_missing" };
    }
    if (connectAuth.token !== auth.token) {
      return { ok: false, reason: "token_mismatch" };
    }
    return { ok: true, method: "token" };
  }

  if (auth.mode === "password") {
    const password = connectAuth?.password;
    if (!auth.password) {
      return { ok: false, reason: "password_missing_config" };
    }
    if (!password) {
      return { ok: false, reason: "password_missing" };
    }
    if (!safeEqual(password, auth.password)) {
      return { ok: false, reason: "password_mismatch" };
    }
    return { ok: true, method: "password" };
  }

  return { ok: false, reason: "unauthorized" };
}
