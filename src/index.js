import {
    API_KEY,
    API_EMAIL,
    ACCOUNT_ID,
    ZONE_ID,
    OWNER_PASSWORD,
    CORS_HEADER_OPTIONS,
    PRX_BANK_URL,
    PRX_PER_PAGE,
    PROTOCOLS,
    PORTS,
    V2RAY_PLUGIN,
    CLASH_USER_AGENT,
    APP_DOMAIN,
    CONVERTER_URL
} from './config.js';
import { CloudflareApi } from './api.js';
import { Document } from './html.js';
import { websocketHandler } from './websocket.js';
import { getPrxList, checkPrxHealth, shuffleArray, reverseWeb, getFlagEmoji } from './utils.js';

export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);

            // Handle WebSocket upgrade requests for proxy clients
            if (request.headers.get("Upgrade") === "websocket") {
                const prxMatch = url.pathname.match(/^\/Free-VPN-Geo-Project\/(.+[:=-]\d+)$/);
                if (prxMatch) {
                    const prxIP = prxMatch[1];
                    return await websocketHandler(request, prxIP);
                }
                // Note: The logic for /ID, /SG has been simplified as it depended on an undefined KV binding.
                // This can be re-added if KV is configured.
                return new Response("Invalid WebSocket path", { status: 400 });
            }

            // Handle HTML subscription page
            if (url.pathname.startsWith("/sub")) {
                return await handleSubPageRequest(request, env);
            }

            // Handle proxy health check endpoint
            if (url.pathname.startsWith("/check")) {
                const target = url.searchParams.get("target");
                if (!target) return new Response("Missing 'target' query parameter", { status: 400 });

                const [ip, port] = target.split(":");
                const result = await checkPrxHealth(ip, port || "443");
                return new Response(JSON.stringify(result), {
                    status: 200,
                    headers: { ...CORS_HEADER_OPTIONS, "Content-Type": "application/json" },
                });
            }

            // Handle API requests
            if (url.pathname.startsWith("/api/v1")) {
                return await handleApiRequest(request, env);
            }

            // Handle IP info request
            if (url.pathname.startsWith("/myip")) {
                return new Response(
                    JSON.stringify({
                        ip: request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip"),
                        colo: request.headers.get("cf-ray")?.split("-")[1],
                        ...request.cf,
                    }), { headers: { ...CORS_HEADER_OPTIONS, "Content-Type": "application/json" } }
                );
            }

            // Default to reverse proxy for other requests
            const targetReversePrx = env.REVERSE_PRX_TARGET || "example.com";
            return await reverseWeb(request, targetReversePrx);

        } catch (err) {
            console.error(err);
            return new Response(`An error occurred: ${err.toString()}`, {
                status: 500,
                headers: { ...CORS_HEADER_OPTIONS },
            });
        }
    },
};

/**
 * Handles requests for the HTML subscription page.
 * @param {Request} request The incoming request.
 * @param {object} env The environment object.
 * @returns {Promise<Response>} The HTML response.
 */
async function handleSubPageRequest(request, env) {
    const url = new URL(request.url);
    const pageMatch = url.pathname.match(/^\/sub\/(\d+)$/);
    const pageIndex = parseInt(pageMatch ? pageMatch[1] : "0", 10);

    // Get filters from query parameters
    const hostname = url.searchParams.get("host") || "ava.game.naver.com";
    const countrySelect = url.searchParams.get("cc")?.toUpperCase();
    const selectedProtocol = url.searchParams.get("vpn");
    const selectedPort = url.searchParams.get("port");
    const searchKeywords = url.searchParams.get("search")?.toLowerCase() || "";

    // Fetch and filter proxies
    let allProxies = await getPrxList(env);
    let filteredProxies = allProxies.filter((prx) => {
        if (countrySelect && countrySelect !== 'ALL' && prx.country !== countrySelect) {
            return false;
        }
        if (searchKeywords) {
            const { prxIP, prxPort, country, org } = prx;
            const searchString = `${prxIP} ${prxPort} ${country} ${org}`.toLowerCase();
            if (!searchString.includes(searchKeywords)) {
                return false;
            }
        }
        return true;
    });

    const result = generateAllConfigsHTML(request, env, hostname, filteredProxies, pageIndex, selectedProtocol, selectedPort);
    return new Response(result, {
        status: 200,
        headers: { "Content-Type": "text/html;charset=utf-8" },
    });
}

/**
 * Handles all /api/v1/ requests.
 * @param {Request} request The incoming request.
 * @param {object} env The environment object.
 * @returns {Promise<Response>} The API response.
 */
async function handleApiRequest(request, env) {
    const url = new URL(request.url);
    const apiPath = url.pathname.replace("/api/v1", "");
    const isApiReady = API_KEY(env) && API_EMAIL(env) && ACCOUNT_ID(env) && ZONE_ID(env);

    if (apiPath.startsWith("/domains")) {
        if (!isApiReady) {
            return new Response("API credentials are not configured", { status: 500, headers: CORS_HEADER_OPTIONS });
        }
        const cloudflareApi = new CloudflareApi(env);
        const domainPath = apiPath.replace("/domains", "");

        if (domainPath === "/get") {
            const domains = await cloudflareApi.getDomainList();
            return new Response(JSON.stringify(domains), { headers: { ...CORS_HEADER_OPTIONS, "Content-Type": "application/json" } });
        }
        if (domainPath === "/put") {
            const domain = url.searchParams.get("domain");
            if (!domain) return new Response("Missing 'domain' parameter", { status: 400, headers: CORS_HEADER_OPTIONS });
            const status = await cloudflareApi.registerDomain(domain);
            return new Response(status.toString(), { status, headers: CORS_HEADER_OPTIONS });
        }
        if (domainPath.startsWith("/delete")) {
            if (url.searchParams.get("password") !== OWNER_PASSWORD(env)) {
                return new Response("Unauthorized", { status: 401, headers: CORS_HEADER_OPTIONS });
            }
            const domainId = url.searchParams.get("id");
            if (!domainId) return new Response("Missing 'id' parameter", { status: 400, headers: CORS_HEADER_OPTIONS });
            const status = await cloudflareApi.deleteDomain(domainId);
            return new Response(status.toString(), { status, headers: CORS_HEADER_OPTIONS });
        }
    }

    if (apiPath.startsWith("/sub")) {
        const finalResult = await generateSubscription(url, env);
        return new Response(finalResult, { status: 200, headers: CORS_HEADER_OPTIONS });
    }

    return new Response("Invalid API path", { status: 404, headers: CORS_HEADER_OPTIONS });
}


/**
 * Generates the HTML page content for a list of proxy configurations.
 */
function generateAllConfigsHTML(request, env, hostName, prxList, page = 0, selectedProtocol = null, selectedPort = null) {
    const startIndex = PRX_PER_PAGE * page;
    const totalProxies = prxList.length;
    const totalPages = Math.ceil(totalProxies / PRX_PER_PAGE) || 1;
    const isApiReady = !!(API_KEY(env) && API_EMAIL(env) && ACCOUNT_ID(env) && ZONE_ID(env));


    const doc = new Document(request, env, prxList, isApiReady);
    doc.setTitle("Free Vless Trojan SS");
    doc.setTotalProxy(totalProxies);
    doc.setPage(page + 1, totalPages);

    const proxiesOnPage = prxList.slice(startIndex, startIndex + PRX_PER_PAGE);

    for (const [index, prx] of proxiesOnPage.entries()) {
        const { prxIP, prxPort, country, org } = prx;
        const uri = new URL(`trojan://${hostName}`); // Start with a base
        uri.searchParams.set("encryption", "none");
        uri.searchParams.set("type", "ws");
        uri.searchParams.set("host", hostName);
        uri.searchParams.set("path", `/Free-VPN-Geo-Project/${prxIP}-${prxPort}`);

        const protocolsToUse = selectedProtocol && selectedProtocol !== 'all' ? [selectedProtocol] : PROTOCOLS;
        const portsToUse = selectedPort && selectedPort !== 'all' ? [parseInt(selectedPort)] : PORTS;

        const generatedConfigs = [];
        for (const port of portsToUse) {
            uri.port = port.toString();
            uri.hash = `${startIndex + index + 1} ${getFlagEmoji(country)} ${org} WS ${port === 443 ? "TLS" : "NTLS"} [${SERVICE_NAME(env)}]`;
            for (const protocol of protocolsToUse) {
                const uuid = crypto.randomUUID();
                uri.protocol = `${protocol}:`;
                uri.searchParams.set("security", port === 443 ? "tls" : "none");
                uri.searchParams.set("sni", port === 80 && protocol === 'vless' ? "" : hostName);

                if (protocol === "ss") {
                    uri.username = btoa(`none:${uuid}`);
                    uri.searchParams.set("plugin", `${V2RAY_PLUGIN}${port === 80 ? "" : ";tls"};mux=0;mode=websocket;path=/Free-VPN-Geo-Project/${prxIP}-${prxPort};host=${hostName}`);
                } else {
                    uri.username = uuid;
                    uri.searchParams.delete("plugin");
                }
                generatedConfigs.push(uri.toString());
            }
        }
        doc.registerProxies({ prxIP, prxPort, country, org }, generatedConfigs);
    }

    const showingFrom = totalProxies > 0 ? startIndex + 1 : 0;
    const showingTo = Math.min(startIndex + PRX_PER_PAGE, totalProxies);
    doc.setPaginationInfo(`Showing ${showingFrom} to ${showingTo} of ${totalProxies} Proxies`);

    doc.addPageButton("Prev", `/sub/${page > 0 ? page - 1 : 0}`, page === 0);
    doc.addPageButton("Next", `/sub/${page < totalPages - 1 ? page + 1 : page}`, page >= totalPages - 1);

    return doc.build();
}

/**
 * Generates a subscription response based on query parameters.
 */
async function generateSubscription(url, env) {
    const filterCC = url.searchParams.get("cc")?.split(",") || [];
    const filterPort = url.searchParams.get("port")?.split(",").map(p => parseInt(p, 10)).filter(p => !isNaN(p)) || PORTS;
    const filterVPN = url.searchParams.get("vpn")?.split(",") || PROTOCOLS;
    const filterLimit = parseInt(url.searchParams.get("limit"), 10) || 10;
    const filterFormat = url.searchParams.get("format") || "raw";
    const fillerDomain = url.searchParams.get("domain") || APP_DOMAIN(env);

    let prxList = await getPrxList(env);
    if (filterCC.length > 0) {
        prxList = prxList.filter((prx) => filterCC.includes(prx.country));
    }
    shuffleArray(prxList);

    const result = [];
    for (const prx of prxList) {
        if (result.length >= filterLimit) break;

        const uri = new URL(`trojan://${fillerDomain}`);
        uri.searchParams.set("encryption", "none");
        uri.searchParams.set("type", "ws");
        uri.searchParams.set("host", fillerDomain);

        for (const port of filterPort) {
            for (const protocol of filterVPN) {
                if (result.length >= filterLimit) break;
                const uuid = crypto.randomUUID();
                uri.protocol = `${protocol}:`;
                uri.port = port.toString();
                uri.searchParams.set("path", `/Free-VPN-Geo-Project/${prx.prxIP}-${prx.prxPort}`);
                uri.searchParams.set("security", port === 443 ? "tls" : "none");
                uri.searchParams.set("sni", port === 80 && protocol === 'vless' ? "" : fillerDomain);
                uri.hash = `${result.length + 1} ${getFlagEmoji(prx.country)} ${prx.org} WS ${port === 443 ? "TLS" : "NTLS"} [${SERVICE_NAME(env)}]`;

                if (protocol === "ss") {
                    uri.username = btoa(`none:${uuid}`);
                    uri.searchParams.set("plugin", `${V2RAY_PLUGIN}${port === 80 ? "" : ";tls"};mux=0;mode=websocket;path=/Free-VPN-Geo-Project/${prx.prxIP}-${prx.prxPort};host=${fillerDomain}`);
                } else {
                    uri.username = uuid;
                    uri.searchParams.delete("plugin");
                }
                result.push(uri.toString());
            }
        }
    }

    let finalResult = result.join("\n");
    if (filterFormat === "v2ray") {
        return btoa(finalResult);
    }
    if (filterFormat === CLASH_USER_AGENT || filterFormat === "sfa" || filterFormat === "bfr") {
        const res = await fetch(CONVERTER_URL, {
            method: "POST",
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: result.join(","),
                format: filterFormat,
                template: "cf",
            }),
        });
        if (res.ok) {
            return await res.text();
        } else {
            return `Error converting subscription: ${res.status} ${res.statusText}`;
        }
    }
    return finalResult;
}