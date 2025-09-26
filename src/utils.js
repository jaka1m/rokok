import {
    CORS_HEADER_OPTIONS,
    PRX_BANK_URL,
    PRX_HEALTH_CHECK_API
} from './config.js';

let cachedPrxList = [];

/**
 * Fetches and parses the proxy list from the bank URL, with caching.
 * @param {object} env The environment object.
 * @returns {Promise<Array<object>>} A promise that resolves to the list of proxies.
 */
export async function getPrxList(env) {
    if (cachedPrxList.length > 0) {
        return cachedPrxList;
    }

    const prxBankUrl = PRX_BANK_URL(env);
    if (!prxBankUrl) {
        throw new Error("No proxy bank URL provided!");
    }

    try {
        const prxBank = await fetch(prxBankUrl);
        if (prxBank.ok) {
            const text = (await prxBank.text()) || "";
            const prxString = text.split("\n").filter(Boolean);
            cachedPrxList = prxString
                .map((entry) => {
                    const [prxIP, prxPort, country, org] = entry.split(",").map(item => item.trim());
                    if (!prxIP || !prxPort) return null;
                    return {
                        prxIP: prxIP,
                        prxPort: prxPort,
                        country: country || "Unknown",
                        org: org || "Unknown Org",
                    };
                })
                .filter(Boolean);
            return cachedPrxList;
        } else {
            console.error(`Failed to fetch proxy list from ${prxBankUrl}. Status: ${prxBank.status}`);
            return [];
        }
    } catch (error) {
        console.error(`Error fetching proxy list: ${error.message}`);
        return [];
    }
}

/**
 * Acts as a simple reverse proxy.
 * @param {Request} request The original request.
 * @param {string} target The target host and port (e.g., "example.com:443").
 * @returns {Promise<Response>} The response from the target.
 */
export async function reverseWeb(request, target) {
    const url = new URL(request.url);
    const [hostname, port] = target.split(":");

    url.hostname = hostname;
    url.port = port || "443";

    const modifiedRequest = new Request(url, request);
    modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

    const response = await fetch(modifiedRequest);

    const newResponse = new Response(response.body, response);
    for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
        newResponse.headers.set(key, value);
    }
    newResponse.headers.set("X-Proxied-By", "Jules-Refactored-Worker");

    return newResponse;
}

/**
 * Checks the health of a given proxy.
 * @param {string} prxIP The IP address of the proxy.
 * @param {string} prxPort The port of the proxy.
 * @returns {Promise<object>} The health check result as a JSON object.
 */
export async function checkPrxHealth(prxIP, prxPort) {
    try {
        const req = await fetch(`${PRX_HEALTH_CHECK_API}?ip=${prxIP}:${prxPort}`);
        if (!req.ok) {
            throw new Error(`Health check API returned status ${req.status}`);
        }
        return await req.json();
    } catch (error) {
        console.error(`Health check failed for ${prxIP}:${prxPort}:`, error);
        return { status: "ERROR", message: error.message };
    }
}

/**
 * Converts a base64 string to an ArrayBuffer.
 * @param {string} base64Str The base64 string.
 * @returns {{earlyData: ArrayBuffer|null, error: Error|null}}
 */
export function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: null, error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

/**
 * Converts an ArrayBuffer to a hex string.
 * @param {ArrayBuffer} buffer The ArrayBuffer to convert.
 * @returns {string} The hex string.
 */
export function arrayBufferToHex(buffer) {
    return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/**
 * Shuffles an array in place.
 * @param {Array<any>} array The array to shuffle.
 */
export function shuffleArray(array) {
    let currentIndex = array.length;
    while (currentIndex !== 0) {
        let randomIndex = Math.floor(Math.random() * currentIndex);
        currentIndex--;
        [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
    }
}

/**
 * Converts a 2-letter ISO country code to a flag emoji.
 * @param {string} isoCode The 2-letter ISO country code.
 * @returns {string} The flag emoji.
 */
export function getFlagEmoji(isoCode) {
    if (!isoCode || isoCode.length !== 2) {
        return "❓"; // Return a question mark for invalid codes
    }
    const codePoints = isoCode
        .toUpperCase()
        .split("")
        .map((char) => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
}