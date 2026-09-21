export interface GeoPoint {
  hostname: string;
  ip: string;
  port: number;
  city: string;
  country: string;
  lat: number;
  lng: number;
}

export const GEO: Record<string, GeoPoint> = {
  "api.z.ai": {
    hostname: "api.z.ai",
    ip: "47.246.22.18",
    port: 443,
    city: "Singapore",
    country: "SG",
    lat: 1.35,
    lng: 103.82,
  },
  "open.bigmodel.cn": {
    hostname: "open.bigmodel.cn",
    ip: "39.104.88.44",
    port: 443,
    city: "Beijing",
    country: "CN",
    lat: 39.9,
    lng: 116.4,
  },
  "api.openai.com": {
    hostname: "api.openai.com",
    ip: "104.18.8.78",
    port: 443,
    city: "San Francisco",
    country: "US",
    lat: 37.77,
    lng: -122.42,
  },
  "api.x.ai": {
    hostname: "api.x.ai",
    ip: "104.18.32.47",
    port: 443,
    city: "Memphis",
    country: "US",
    lat: 35.15,
    lng: -90.05,
  },
  "github.com": {
    hostname: "github.com",
    ip: "140.82.112.4",
    port: 443,
    city: "Washington",
    country: "US",
    lat: 38.9,
    lng: -77.04,
  },
  "registry.npmjs.org": {
    hostname: "registry.npmjs.org",
    ip: "104.16.24.34",
    port: 443,
    city: "San Jose",
    country: "US",
    lat: 37.34,
    lng: -121.89,
  },
  "pypi.org": {
    hostname: "pypi.org",
    ip: "151.101.0.223",
    port: 443,
    city: "Ashburn",
    country: "US",
    lat: 39.04,
    lng: -77.49,
  },
  "proxy.golang.org": {
    hostname: "proxy.golang.org",
    ip: "142.250.185.81",
    port: 443,
    city: "Council Bluffs",
    country: "US",
    lat: 41.26,
    lng: -95.86,
  },
  "crates.io": {
    hostname: "crates.io",
    ip: "13.32.99.12",
    port: 443,
    city: "Frankfurt",
    country: "DE",
    lat: 50.11,
    lng: 8.68,
  },
  "registry.npmjs.org.cn": {
    hostname: "npmmirror.com",
    ip: "47.246.21.9",
    port: 443,
    city: "Hangzhou",
    country: "CN",
    lat: 30.27,
    lng: 120.15,
  },
  "objects.githubusercontent.com": {
    hostname: "objects.githubusercontent.com",
    ip: "185.199.108.133",
    port: 443,
    city: "Amsterdam",
    country: "NL",
    lat: 52.37,
    lng: 4.9,
  },
  "cdn.jsdelivr.net": {
    hostname: "cdn.jsdelivr.net",
    ip: "151.101.1.229",
    port: 443,
    city: "Tokyo",
    country: "JP",
    lat: 35.68,
    lng: 139.69,
  },
  "transfer.sh": {
    hostname: "transfer.sh",
    ip: "116.203.110.91",
    port: 443,
    city: "Nuremberg",
    country: "DE",
    lat: 49.45,
    lng: 11.08,
  },
  "file.io": {
    hostname: "file.io",
    ip: "104.26.8.78",
    port: 443,
    city: "Los Angeles",
    country: "US",
    lat: 34.05,
    lng: -118.24,
  },
  "0x0.st": {
    hostname: "0x0.st",
    ip: "135.181.113.4",
    port: 443,
    city: "Helsinki",
    country: "FI",
    lat: 60.17,
    lng: 24.94,
  },
  "webhook.site": {
    hostname: "webhook.site",
    ip: "46.30.213.165",
    port: 443,
    city: "Copenhagen",
    country: "DK",
    lat: 55.68,
    lng: 12.57,
  },
  "zcode.z.ai": {
    hostname: "zcode.z.ai",
    ip: "39.104.88.80",
    port: 443,
    city: "Beijing",
    country: "CN",
    lat: 39.9,
    lng: 116.4,
  },
  "oss-cn-hangzhou.aliyuncs.com": {
    hostname: "oss-cn-hangzhou.aliyuncs.com",
    ip: "118.31.164.22",
    port: 443,
    city: "Hangzhou",
    country: "CN",
    lat: 30.27,
    lng: 120.15,
  },
  "api.anthropic.com": {
    hostname: "api.anthropic.com",
    ip: "160.79.104.10",
    port: 443,
    city: "San Francisco",
    country: "US",
    lat: 37.77,
    lng: -122.42,
  },
  "openrouter.ai": {
    hostname: "openrouter.ai",
    ip: "104.26.4.73",
    port: 443,
    city: "San Francisco",
    country: "US",
    lat: 37.77,
    lng: -122.42,
  },
  "generativelanguage.googleapis.com": {
    hostname: "generativelanguage.googleapis.com",
    ip: "142.250.185.74",
    port: 443,
    city: "Council Bluffs",
    country: "US",
    lat: 41.26,
    lng: -95.86,
  },
};

export const ORIGIN = { lat: 35.68, lng: 139.69, city: "Tokyo" };

export function extractHost(text: string): string | undefined {
  const m = /\bhttps?:\/\/([^/\s:?#]+)/i.exec(text);
  return m?.[1]?.toLowerCase();
}

export function project(lng: number, lat: number, w: number, h: number) {
  const padX = w * 0.04;
  const padY = h * 0.08;
  const x = padX + ((lng + 180) / 360) * (w - padX * 2);
  const y = padY + ((90 - lat) / 180) * (h - padY * 2);
  return { x, y };
}
