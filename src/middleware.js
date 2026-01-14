import { NextResponse } from "next/server";

const isPrivateIp = (ip = "") =>
  ip.startsWith("127.") ||
  ip === "::1" ||
  ip.startsWith("10.") ||
  ip.startsWith("192.168.") ||
  /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
  ip.startsWith("fc") ||
  ip.startsWith("fd");

const stripPort = (ip = "") => ip.replace(/:\d+$/, "");
const normalizeIp = (ip = "") => {
  const stripped = stripPort(ip.trim()).replace(/^\[|\]$/g, "");
  if (stripped === ":" || stripped === "") return "";
  // Handle IPv4-mapped IPv6 (::ffff:127.0.0.1)
  if (stripped.startsWith("::ffff:")) return stripped.replace("::ffff:", "");
  return stripped;
};

const getClientIp = (req) => {
  const forwardedFor = req.headers.get("x-forwarded-for");
  const forwardedIp = forwardedFor ? normalizeIp(forwardedFor.split(",")[0]) : "";
  const directIp = normalizeIp(req.ip || "");
  return directIp || forwardedIp;
};

export function middleware(req) {
  // Best-effort Host + client IP validation. Public deployments must still sit behind a reverse proxy that blocks spoofed Host headers.
  const host = req.headers.get("host");
  const port = process.env.PORT || 3000;
  let allowedHosts = [`localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`];
  const allowAllHosts = process.env.HOMEPAGE_ALLOWED_HOSTS === "*";
  if (process.env.HOMEPAGE_ALLOWED_HOSTS) {
    allowedHosts = allowedHosts.concat(process.env.HOMEPAGE_ALLOWED_HOSTS.split(","));
  }

  const clientIp = getClientIp(req);
  const allowedIps = process.env.HOMEPAGE_ALLOWED_IPS
    ? process.env.HOMEPAGE_ALLOWED_IPS.split(",")
        .map((ip) => stripPort(ip.trim()))
        .filter(Boolean)
    : [];

  const hostAllowed = allowAllHosts || (host && allowedHosts.includes(host));
  const ipAllowed = !clientIp || isPrivateIp(clientIp) || allowedIps.includes(clientIp);

  if (!hostAllowed || !ipAllowed) {
    // eslint-disable-next-line no-console
    console.error(
      `Host/IP validation failed for host=${host || "unknown"} ip=${clientIp || "unknown"}. Hint: Set HOMEPAGE_ALLOWED_HOSTS / HOMEPAGE_ALLOWED_IPS to allow this origin.`,
    );
    return NextResponse.json({ error: "Host validation failed. See logs for more details." }, { status: 400 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: "/api/:path*",
};
