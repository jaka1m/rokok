// Konfigurasi utama aplikasi
// Diambil dari environment variables untuk keamanan
export const ROOT_DOMAIN = (env) => env.ROOT_DOMAIN || "example.com";
export const SERVICE_NAME = (env) => env.SERVICE_NAME || "worker-name";
export const API_KEY = (env) => env.API_KEY;
export const API_EMAIL = (env) => env.API_EMAIL;
export const ACCOUNT_ID = (env) => env.ACCOUNT_ID;
export const ZONE_ID = (env) => env.ZONE_ID;
export const OWNER_PASSWORD = (env) => env.OWNER_PASSWORD;

// Variabel untuk tautan eksternal dan data
export const WHATSAPP_NUMBER = "082339191527";
export const TELEGRAM_USERNAME = "sampiiii";
export const PRX_BANK_URL = (env) => env.PRX_BANK_URL || "https://raw.githubusercontent.com/jaka2m/botak/refs/heads/main/cek/proxyList.txt";
export const DONATE_LINK = "https://github.com/jaka1m/project/raw/main/BAYAR.jpg";
export const BAD_WORDS_LIST = "https://gist.githubusercontent.com/adierebel/a69396d79b787b84d89b45002cb37cd6/raw/6df5f8728b18699496ad588b3953931078ab9cf1/kata-kasar.txt";

// Konfigurasi teknis
export const PORTS = [443, 80];
export const PROTOCOLS = ["trojan", "vless", "ss"];
export const V2RAY_PLUGIN = "v2ray-plugin";
export const CLASH_USER_AGENT = "clash";

export const APP_DOMAIN = (env) => `${SERVICE_NAME(env)}.${ROOT_DOMAIN(env)}`;

// Konfigurasi DNS
export const DNS_SERVER_ADDRESS = "8.8.8.8";
export const DNS_SERVER_PORT = 53;

// Konfigurasi API eksternal
export const PRX_HEALTH_CHECK_API = "https://geovpn.vercel.app/check";
export const CONVERTER_URL = "https://api.foolvpn.me/convert";

// Konfigurasi halaman dan WebSocket
export const PRX_PER_PAGE = 24;
export const WS_READY_STATE_OPEN = 1;
export const WS_READY_STATE_CLOSING = 2;

// Konfigurasi CORS
export const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};