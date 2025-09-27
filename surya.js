import { connect } from "cloudflare:sockets";

// Variables
const rootDomain = "gpj2.dpdns.org"; // Ganti dengan domain utama kalian
const serviceName = "nautica"; // Ganti dengan nama workers kalian
const apiKey = "673fee2d6747b90db9a90e9279195974d01f9"; // Ganti dengan Global API key kalian (https://dash.cloudflare.com/profile/api-tokens)
const apiEmail = "paoandest@gmail.com"; // Ganti dengan email yang kalian gunakan
const accountID = "c4682365bae93b9e2a94d6ba827c82a9"; // Ganti dengan Account ID kalian (https://dash.cloudflare.com -> Klik domain yang kalian gunakan)
const zoneID = "dc7a50828fc5e7cacd27318d4e7ceee5"; // Ganti dengan Zone ID kalian (https://dash.cloudflare.com -> Klik domain yang kalian gunakan)
const ownerPassword = "ambe123";
let isApiReady = false;
let prxIP = "";
let cachedPrxList = [];

// Constant
const WHATSAPP_NUMBER = "082339191527";
const TELEGRAM_USERNAME = "sampiiii";
const horse = "dHJvamFu";
const flash = "dmxlc3M=";
const v2 = "djJyYXk=";
const neko = "Y2xhc2g=";

const APP_DOMAIN = `${serviceName}.${rootDomain}`;
const PORTS = [443, 80];
const PROTOCOLS = [atob(horse), atob(flash), "ss"];
const PRX_BANK_URL = "https://raw.githubusercontent.com/jaka2m/botak/refs/heads/main/cek/proxyList.txt";
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const PRX_HEALTH_CHECK_API = "https://geovpn.vercel.app/check";
const CONVERTER_URL = "https://api.foolvpn.me/convert";
const DONATE_LINK = "https://github.com/jaka1m/project/raw/main/BAYAR.jpg";
const BAD_WORDS_LIST =
  "https://gist.githubusercontent.com/adierebel/a69396d79b787b84d89b45002cb37cd6/raw/6df5f8728b18699496ad588b3953931078ab9cf1/kata-kasar.txt";
const PRX_PER_PAGE = 24;
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

async function getKVPrxList(kvPrxUrl) {
  if (!kvPrxUrl) {
    return {};
  }

  const kvPrx = await fetch(kvPrxUrl);
  if (kvPrx.status == 200) {
    return await kvPrx.json();
  } else {
    return {};
  }
}

async function getPrxList(prxBankUrl = PRX_BANK_URL) {
  /**
   * Format:
   *
   * <IP>,<Port>,<Country ID>,<ORG>
   * Contoh:
   * 1.1.1.1,443,SG,Cloudflare Inc.
   */
  if (!prxBankUrl) {
    throw new Error("No URL Provided!");
  }

  const prxBank = await fetch(prxBankUrl);
  if (prxBank.status == 200) {
    const text = (await prxBank.text()) || "";

    const prxString = text.split("\n").filter(Boolean);
    cachedPrxList = prxString
      .map((entry) => {
        const [prxIP, prxPort, country, org] = entry.split(",").map(item => item.trim());
        return {
          prxIP: prxIP || "Unknown",
          prxPort: prxPort || "Unknown",
          country: country || "Unknown",
          org: org || "Unknown Org",
        };
      })
      .filter(Boolean);
  }

  return cachedPrxList;
}

async function reverseWeb(request, target, targetPath) {
  const targetUrl = new URL(request.url);
  const targetChunk = target.split(":");

  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk[1]?.toString() || "443";
  targetUrl.pathname = targetPath || targetUrl.pathname;

  const modifiedRequest = new Request(targetUrl, request);

  modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

  const response = await fetch(modifiedRequest);

  const newResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
    newResponse.headers.set(key, value);
  }
  newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");

  return newResponse;
}

function getAllConfig(request, hostName, prxList, page = 0, selectedProtocol = null, selectedPort = null) {
    const startIndex = PRX_PER_PAGE * page;
    const totalProxies = prxList.length;
    const totalPages = Math.ceil(totalProxies / PRX_PER_PAGE) || 1;

    try {
        const uuid = crypto.randomUUID();

        // If a custom host is selected, the host/SNI will be a combination.
        // Otherwise, it's just the application's domain.
        const effectiveHost = hostName === APP_DOMAIN ? APP_DOMAIN : `${hostName}.${APP_DOMAIN}`;

        // Build URI
        // The address is the selected host (e.g., ava.game.naver.com or the app domain)
        const uri = new URL(`${atob(horse)}://${hostName}`);
        uri.searchParams.set("encryption", "none");
        uri.searchParams.set("type", "ws");
        uri.searchParams.set("host", effectiveHost);

        // Build HTML
        const document = new Document(request);
        document.setTitle("Free Vless Trojan SS");
        document.setTotalProxy(totalProxies);
        document.setPage(page + 1, totalPages);

        for (let i = startIndex; i < startIndex + PRX_PER_PAGE; i++) {
            const prx = prxList[i];
            if (!prx) break;

            const { prxIP, prxPort, country, org } = prx;

            uri.searchParams.set("path", `/Free-VPN-Geo-Project/${prxIP}-${prxPort}`);

            const protocolsToUse = selectedProtocol && selectedProtocol !== 'all' ? [selectedProtocol] : PROTOCOLS;
            const portsToUse = selectedPort && selectedPort !== 'all' ? [parseInt(selectedPort)] : PORTS;

            const prxs = [];
            for (const port of portsToUse) {
                uri.port = port.toString();
                uri.hash = `${i + 1} ${getFlagEmoji(country)} ${org} WS ${port == 443 ? "TLS" : "NTLS"} [${serviceName}]`;
                for (const protocol of protocolsToUse) {
                    // Special exceptions
                    if (protocol === "ss") {
                        uri.username = btoa(`none:${uuid}`);
                        uri.searchParams.set(
                            "plugin",
                            `${atob(v2)}-plugin${
                                port == 80 ? "" : ";tls"
                            };mux=0;mode=websocket;path=/Free-VPN-Geo-Project/${prxIP}-${prxPort};host=${effectiveHost}`
                        );
                    } else {
                        uri.username = uuid;
                        uri.searchParams.delete("plugin");
                    }

                    uri.protocol = protocol;
                    uri.searchParams.set("security", port == 443 ? "tls" : "none");
                    uri.searchParams.set("sni", port == 80 && protocol == atob(flash) ? "" : effectiveHost);

                    // Build VPN URI
                    prxs.push(uri.toString());
                }
            }
            document.registerProxies(
                {
                    prxIP,
                    prxPort,
                    country,
                    org,
                },
                prxs
            );
        }

        // Build pagination
        const showingFrom = totalProxies > 0 ? startIndex + 1 : 0;
        const showingTo = Math.min(startIndex + PRX_PER_PAGE, totalProxies);
        document.setPaginationInfo(`Showing ${showingFrom} to ${showingTo} of ${totalProxies} Proxies`);

        // Prev button
        document.addPageButton("Prev", `/sub/${page > 0 ? page - 1 : 0}`, page === 0);


        // Numbered buttons

        // Next button
        document.addPageButton("Next", `/sub/${page < totalPages - 1 ? page + 1 : page}`, page >= totalPages - 1);

        return document.build();
    } catch (error) {
        return `An error occurred while generating the ${atob(flash).toUpperCase()} configurations. ${error}`;
    }
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");

      // Gateway check
      if (apiKey && apiEmail && accountID && zoneID) {
        isApiReady = true;
      }

      // Handle prx client
      if (upgradeHeader === "websocket") {
        const prxMatch = url.pathname.match(
          /^\/Free-VPN-Geo-Project\/(.+[:=-]\d+)$/
        );

        if (url.pathname.length == 3 || url.pathname.match(",")) {
          // Contoh: /ID, /SG, dll
          const prxKeys = url.pathname.replace("/", "").toUpperCase().split(",");
          const prxKey = prxKeys[Math.floor(Math.random() * prxKeys.length)];
          const kvPrx = await getKVPrxList(env.KV_PRX_URL);

          prxIP = kvPrx[prxKey][Math.floor(Math.random() * kvPrx[prxKey].length)];

          return await websocketHandler(request);
        } else if (prxMatch) {
          prxIP = prxMatch[1];
          return await websocketHandler(request);
        }
      }

      if (url.pathname.startsWith("/sub")) {
        const page = url.pathname.match(/^\/sub\/(\d+)$/);
        const pageIndex = parseInt(page ? page[1] : "0");

        // Queries
        const hostname = url.searchParams.get("host") || APP_DOMAIN;
        const countrySelect = url.searchParams.get("cc")?.toUpperCase();
        const selectedProtocol = url.searchParams.get("vpn");
        const selectedPort = url.searchParams.get("port");
        const searchKeywords = url.searchParams.get("search")?.toLowerCase() || "";
        const prxBankUrl = url.searchParams.get("prx-list") || env.PRX_BANK_URL;
        let prxList = (await getPrxList(prxBankUrl)).filter((prx) => {
          // Filter prxs by Country
          if (countrySelect && countrySelect !== 'ALL') {
            if (prx.country !== countrySelect) return false;
          }

          // Filter by search keywords
          if (searchKeywords) {
              const { prxIP, prxPort, country, org } = prx;
              if (
                  !prxIP.toLowerCase().includes(searchKeywords) &&
                  !prxPort.toLowerCase().includes(searchKeywords) &&
                  !country.toLowerCase().includes(searchKeywords) &&
                  !org.toLowerCase().includes(searchKeywords)
              ) {
                  return false;
              }
          }

          return true;
        });

        const result = getAllConfig(request, hostname, prxList, pageIndex, selectedProtocol, selectedPort);
        return new Response(result, {
          status: 200,
          headers: { "Content-Type": "text/html;charset=utf-8" },
        });
      } else if (url.pathname.startsWith("/check")) {
        const target = url.searchParams.get("target").split(":");
        const result = await checkPrxHealth(target[0], target[1] || "443");

        return new Response(JSON.stringify(result), {
          status: 200,
          headers: {
            ...CORS_HEADER_OPTIONS,
            "Content-Type": "application/json",
          },
        });
      } else if (url.pathname.startsWith("/api/v1")) {
        const apiPath = url.pathname.replace("/api/v1", "");

        if (apiPath.startsWith("/domains")) {
          if (!isApiReady) {
            return new Response("Api not ready", {
              status: 500,
            });
          }

          const wildcardApiPath = apiPath.replace("/domains", "");
          const cloudflareApi = new CloudflareApi();

          if (wildcardApiPath == "/get") {
            const domains = await cloudflareApi.getDomainList();
            return new Response(JSON.stringify(domains), {
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            });
          } else if (wildcardApiPath == "/put") {
            const domain = url.searchParams.get("domain");
            const register = await cloudflareApi.registerDomain(domain);

            return new Response(register.toString(), {
              status: register,
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            });
          } else if (wildcardApiPath.startsWith("/delete")) {
            const domainId = url.searchParams.get("id");
            const password = url.searchParams.get("password");

            if (password !== ownerPassword) {
              return new Response("Unauthorized", {
                status: 401,
                headers: { ...CORS_HEADER_OPTIONS },
              });
            }

            if (!domainId) {
              return new Response("Domain ID is required", {
                status: 400,
                headers: { ...CORS_HEADER_OPTIONS },
              });
            }

            const result = await cloudflareApi.deleteDomain(domainId);
            return new Response(result.toString(), {
              status: result,
              headers: { ...CORS_HEADER_OPTIONS },
            });
          }
        } else if (apiPath.startsWith("/sub")) {
          const filterCC = url.searchParams.get("cc")?.split(",") || [];
          const filterPort = url.searchParams.get("port")?.split(",") || PORTS;
          const filterVPN = url.searchParams.get("vpn")?.split(",") || PROTOCOLS;
          const filterLimit = parseInt(url.searchParams.get("limit")) || 10;
          const filterFormat = url.searchParams.get("format") || "raw";
          const fillerDomain = url.searchParams.get("domain") || APP_DOMAIN;
          const effectiveHost = fillerDomain === APP_DOMAIN ? APP_DOMAIN : `${fillerDomain}.${APP_DOMAIN}`;

          const prxBankUrl = url.searchParams.get("prx-list") || env.PRX_BANK_URL;
          const prxList = await getPrxList(prxBankUrl)
            .then((prxs) => {
              // Filter CC
              if (filterCC.length) {
                return prxs.filter((prx) => filterCC.includes(prx.country));
              }
              return prxs;
            })
            .then((prxs) => {
              // shuffle result
              shuffleArray(prxs);
              return prxs;
            });

          const uuid = crypto.randomUUID();
          const result = [];
          for (const prx of prxList) {
            const uri = new URL(`${atob(horse)}://${fillerDomain}`);
            uri.searchParams.set("encryption", "none");
            uri.searchParams.set("type", "ws");
            uri.searchParams.set("host", effectiveHost);

            for (const port of filterPort) {
              for (const protocol of filterVPN) {
                if (result.length >= filterLimit) break;

                uri.protocol = protocol;
                uri.port = port.toString();
                if (protocol == "ss") {
                  uri.username = btoa(`none:${uuid}`);
                  uri.searchParams.set(
                    "plugin",
                    `${atob(v2)}-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/Free-VPN-Geo-Project/${prxIP}-${
                      prx.prxPort
                    };host=${effectiveHost}`
                  );
                } else {
                  uri.username = uuid;
                }

                uri.searchParams.set("security", port == 443 ? "tls" : "none");
                uri.searchParams.set("sni", port == 80 && protocol == atob(flash) ? "" : effectiveHost);
                uri.searchParams.set("path", `/Free-VPN-Geo-Project/${prxIP}-${prx.prxPort}`);

                uri.hash = `${result.length + 1} ${getFlagEmoji(prx.country)} ${prx.org} WS ${
                  port == 443 ? "TLS" : "NTLS"
                } [${serviceName}]`;
                result.push(uri.toString());
              }
            }
          }

          let finalResult = "";
          switch (filterFormat) {
            case "raw":
              finalResult = result.join("\n");
              break;
            case atob(v2):
              finalResult = btoa(result.join("\n"));
              break;
            case atob(neko):
            case "sfa":
            case "bfr":
              const res = await fetch(CONVERTER_URL, {
                method: "POST",
                body: JSON.stringify({
                  url: result.join(","),
                  format: filterFormat,
                  template: "cf",
                }),
              });
              if (res.status == 200) {
                finalResult = await res.text();
              } else {
                return new Response(res.statusText, {
                  status: res.status,
                  headers: {
                    ...CORS_HEADER_OPTIONS,
                  },
                });
              }
              break;
          }

          return new Response(finalResult, {
            status: 200,
            headers: {
              ...CORS_HEADER_OPTIONS,
            },
          });
        } else if (apiPath.startsWith("/myip")) {
          return new Response(
            JSON.stringify({
              ip:
                request.headers.get("cf-connecting-ipv6") ||
                request.headers.get("cf-connecting-ip") ||
                request.headers.get("x-real-ip"),
              colo: request.headers.get("cf-ray")?.split("-")[1],
              ...request.cf,
            }),
            {
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            }
          );
        }
      }

      const targetReversePrx = env.REVERSE_PRX_TARGET || "example.com";
      return await reverseWeb(request, targetReversePrx);
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: {
          ...CORS_HEADER_OPTIONS,
        },
      });
    }
  },
};

async function websocketHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = {
    value: null,
  };
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS) {
            return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const protocol = await protocolSniffer(chunk);
          let protocolHeader;

          if (protocol === atob(horse)) {
            protocolHeader = readHorseHeader(chunk);
          } else if (protocol === atob(flash)) {
            protocolHeader = readFlashHeader(chunk);
          } else if (protocol === "ss") {
            protocolHeader = readSsHeader(chunk);
          } else {
            throw new Error("Unknown Protocol!");
          }

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
            } else {
              // return handleUDPOutbound(protocolHeader.addressRemote, protocolHeader.portRemote, chunk, webSocket, protocolHeader.version, log);
              throw new Error("UDP only support for DNS port 53");
            }
          }

          if (isDNS) {
            return handleUDPOutbound(
              DNS_SERVER_ADDRESS,
              DNS_SERVER_PORT,
              chunk,
              webSocket,
              protocolHeader.version,
              log
            );
          }

          handleTCPOutBound(
            remoteSocketWrapper,
            protocolHeader.addressRemote,
            protocolHeader.portRemote,
            protocolHeader.rawClientData,
            webSocket,
            protocolHeader.version,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) {
      if (horseDelimiter[2] === 0x01 || horseDelimiter[2] === 0x03 || horseDelimiter[2] === 0x7f) {
        if (horseDelimiter[3] === 0x01 || horseDelimiter[3] === 0x03 || horseDelimiter[3] === 0x04) {
          return atob(horse);
        }
      }
    }
  }

  const flashDelimiter = new Uint8Array(buffer.slice(1, 17));
  // Hanya mendukung UUID v4
  if (arrayBufferToHex(flashDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
    return atob(flash);
  }

  return "ss"; // default
}

async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  responseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();

    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = await connectAndWrite(
      prxIP.split(/[:=-]/)[0] || addressRemote,
      prxIP.split(/[:=-]/)[1] || portRemote
    );
    tcpSocket.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

async function handleUDPOutbound(targetAddress, targetPort, udpChunk, webSocket, responseHeader, log) {
  try {
    let protocolHeader = responseHeader;
    const tcpSocket = connect({
      hostname: targetAddress,
      port: targetPort,
    });

    log(`Connected to ${targetAddress}:${targetPort}`);

    const writer = tcpSocket.writable.getWriter();
    await writer.write(udpChunk);
    writer.releaseLock();

    await tcpSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            if (protocolHeader) {
              webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
              protocolHeader = null;
            } else {
              webSocket.send(chunk);
            }
          }
        },
        close() {
          log(`UDP connection to ${targetAddress} closed`);
        },
        abort(reason) {
          console.error(`UDP connection to ${targetPort} aborted due to ${reason}`);
        },
      })
    );
  } catch (e) {
    console.error(`Error while handling UDP outbound, error ${e.message}`);
  }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

function readSsHeader(ssBuffer) {
  const view = new DataView(ssBuffer);

  const addressType = view.getUint8(0);
  let addressLength = 0;
  let addressValueIndex = 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `Invalid addressType for SS: ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `Destination address empty, address type is: ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 2,
    rawClientData: ssBuffer.slice(portIndex + 2),
    version: null,
    isUDP: portRemote == 53,
  };
}

function readFlashHeader(buffer) {
  const version = new Uint8Array(buffer.slice(0, 1));
  let isUDP = false;

  const optLength = new Uint8Array(buffer.slice(17, 18))[0];

  const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (cmd === 1) {
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${cmd} is not supported`,
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1));

  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2: // For Domain
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: // For IPv6
      addressLength = 16;
      const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`,
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    rawClientData: buffer.slice(addressValueIndex + addressLength),
    version: new Uint8Array([version[0], 0]),
    isUDP: isUDP,
  };
}

function readHorseHeader(buffer) {
  const dataBuffer = buffer.slice(58);
  if (dataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid request data",
    };
  }

  let isUDP = false;
  const view = new DataView(dataBuffer);
  const cmd = view.getUint8(0);
  if (cmd == 3) {
    isUDP = true;
  } else if (cmd != 1) {
    throw new Error("Unsupported command type!");
  }

  let addressType = view.getUint8(1);
  let addressLength = 0;
  let addressValueIndex = 2;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3: // For Domain
      addressLength = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4: // For IPv6
      addressLength = 16;
      const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = dataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 4,
    rawClientData: dataBuffer.slice(portIndex + 4),
    version: null,
    isUDP: isUDP,
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

async function checkPrxHealth(prxIP, prxPort) {
  const req = await fetch(`${PRX_HEALTH_CHECK_API}?ip=${prxIP}:${prxPort}`);
  return await req.json();
}

// Helpers
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function shuffleArray(array) {
  let currentIndex = array.length;

  // While there remain elements to shuffle...
  while (currentIndex != 0) {
    // Pick a remaining element...
    let randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;

    // And swap it with the current element.
    [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
  }
}

function reverse(s) {
  return s.split("").reverse().join("");
}

function getFlagEmoji(isoCode) {
  const codePoints = isoCode
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

// CloudflareApi Class
class CloudflareApi {
  constructor() {
    this.bearer = `Bearer ${apiKey}`;
    this.accountID = accountID;
    this.zoneID = zoneID;
    this.apiEmail = apiEmail;
    this.apiKey = apiKey;

    this.headers = {
      Authorization: this.bearer,
      "X-Auth-Email": this.apiEmail,
      "X-Auth-Key": this.apiKey,
    };
  }

  async getDomainList() {
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      headers: {
        ...this.headers,
      },
    });

    if (res.status == 200) {
      const respJson = await res.json();

      return respJson.result
        .filter((data) => data.service == serviceName)
        .map((data) => ({ id: data.id, hostname: data.hostname }));
    }

    return [];
  }

  async registerDomain(domain) {
    domain = domain.toLowerCase();
    const registeredDomains = await this.getDomainList();

    if (!domain.endsWith(rootDomain)) return 400;
    if (registeredDomains.includes(domain)) return 409;

    try {
      const domainTest = await fetch(`https://${domain.replaceAll("." + APP_DOMAIN, "")}`);
      if (domainTest.status == 530) return domainTest.status;

      const badWordsListRes = await fetch(BAD_WORDS_LIST);
      if (badWordsListRes.status == 200) {
        const badWordsList = (await badWordsListRes.text()).split("\n");
        for (const badWord of badWordsList) {
          if (domain.includes(badWord.toLowerCase())) {
            return 403;
          }
        }
      } else {
        return 403;
      }
    } catch (e) {
      return 400;
    }

    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      method: "PUT",
      body: JSON.stringify({
        environment: "production",
        hostname: domain,
        service: serviceName,
        zone_id: this.zoneID,
      }),
      headers: {
        ...this.headers,
      },
    });

    return res.status;
  }

  async deleteDomain(domainId) {
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains/${domainId}`;
    const res = await fetch(url, {
      method: "DELETE",
      headers: {
        ...this.headers,
      },
    });

    return res.status;
  }
}


let baseHTML = `
<!DOCTYPE html>
<html lang="en" id="html" class="scroll-auto scrollbar-hide dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>Geo-VPN | VPN Tunnel | CloudFlare</title>

    <meta name="description" content="Akun Vless Gratis. Geo-VPN offers free Vless accounts with Cloudflare and Trojan support. Secure and fast VPN tunnel services.">
    <meta name="keywords" content="Geo-VPN, Free Vless, Vless CF, Trojan CF, Cloudflare, VPN Tunnel, Akun Vless Gratis">
    <meta name="author" content="Geo-VPN">
    <meta name="robots" content="index, follow, noarchive, max-snippet:-1, max-image-preview:large, max-video-preview:-1">

    <link rel="icon" href="https://geoproject.biz.id/circle-flags/bote.png">
    <link rel="apple-touch-icon" href="https://geoproject.biz.id/circle-flags/bote.png">

    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/lozad/dist/lozad.min.js"></script>
    
    <script src="https://cdn.jsdelivr.net/npm/js-yaml@4.1.0/dist/js-yaml.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/js/all.min.js"></script>
      <script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>
      
    
    <style>
        /* For Webkit-based browsers (Chrome, Safari and Opera) */
        .scrollbar-hide::-webkit-scrollbar {
            display: none;
        }
        /* For IE, Edge and Firefox */
        .scrollbar-hide {
            -ms-overflow-style: none; /* IE and Edge */
            scrollbar-width: none; /* Firefox */
        }
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap');

        /* Glassmorphism Effect */
        .glass-effect {
            background-color: rgba(42, 42, 47, 0.6);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid rgba(0, 224, 183, 0.3);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .glass-effect-light {
            background-color: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            border: 1px solid rgba(0, 224, 183, 0.2);
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        
        /* CSS untuk animasi bendera berputar */
.flag-spin {
  animation: spin-around 4s linear infinite alternate; /* 4s: durasi, infinite: berulang, alternate: bolak-balik */
  transform-origin: center center; /* Pastikan rotasi dari tengah */
}

@keyframes spin-around {
  0% {
    transform: rotateY(0deg); /* Posisi awal, tidak berputar */
  }
  50% {
    transform: rotateY(180deg); /* Berputar 180 derajat (menghadap ke belakang) */
  }
  100% {
    transform: rotateY(0deg); /* Kembali ke posisi awal (menghadap ke depan) */
  }
}
    </style>

    <script>
        tailwind.config = {
            darkMode: 'selector',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Poppins', 'sans-serif'],
                    },
                    colors: {
                        'primary-dark': '#1c1c20',
                        'secondary-dark': '#2a2a2f',
                        'text-light': '#f0f0f5',
                        'accent-cyan': '#00e0b7',
                        'accent-blue': '#4a90e2',
                    },
                },
            },
        };
    </script>
    
    
    
    
    
    <script>
        tailwind.config = { darkMode: 'selector', theme: { extend: {
            colors: {
                'accent-blue': '#66b5e8',
                'accent-purple': '#a466e8',
            }
        } } };
      </script>
      <style>
        /* Custom Styles for Modern/Elegant Look */
        
        /* START: PENINGKATAN EFEK 3D */
        body {
            perspective: 1000px; 
        }
        .main-container {
          background: rgba(30, 41, 59, 0.8); 
          backdrop-filter: blur(8px);
          border-radius: 1.5rem;
          box-shadow: 
            0 25px 50px rgba(0, 0, 0, 0.7), 
            0 0 15px rgba(102, 181, 232, 0.2) inset, 
            0 0 5px rgba(0, 0, 0, 0.5); 
          border: 1px solid rgba(100, 116, 139, 0.4); 
          padding: 2rem;
          margin-bottom: 2rem;
          transform: translateZ(20px); 
        }
        .btn-gradient {
          background: linear-gradient(to right, var(--tw-color-accent-blue), var(--tw-color-accent-purple));
          box-shadow: 0 4px 10px rgba(0, 0, 0, 0.4), inset 0 1px 1px rgba(255, 255, 255, 0.2), inset 0 -3px 5px rgba(0, 0, 0, 0.3);
          transition: all 0.3s ease;
        }
        .btn-gradient:hover:not(:disabled) {
          box-shadow: 0 1px 5px rgba(0, 0, 0, 0.4), inset 0 1px 5px rgba(0, 0, 0, 0.4), inset 0 0 10px rgba(102, 181, 232, 0.8);
          transform: translateY(1px);
        }
        .input-group {
          background-color: rgba(30, 41, 59, 0.6); 
          border-radius: 0.75rem; 
          padding: 1rem; 
          border: 1px solid rgba(100, 116, 139, 0.3);
          box-shadow: inset 0 0 5px rgba(0, 0, 0, 0.5); 
        }
        .input-dark, .input-group textarea, .input-group select {
          background-color: #1f2937; 
          color: #ffffff;
          border: 1px solid #475569; 
          border-radius: 0.5rem;
          box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.6); 
          transition: border-color 0.2s, box-shadow 0.2s;
        }
        .input-dark:focus, .input-group textarea:focus, .input-group select:focus {
          border-color: var(--tw-color-accent-blue);
          box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.6), 0 0 5px var(--tw-color-accent-blue); 
        }
        .action-btn {
            background-color: #1e293b; 
            color: #94a3b8;
            border: 1px solid #475569;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1);
            transition: all 0.2s;
        }
        .action-btn:hover {
            background-color: #334155; 
            color: white;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.5), inset 0 1px 5px rgba(0, 0, 0, 0.6);
            transform: translateY(1px);
        }
        /* END: PENINGKATAN EFEK 3D */


        .table-dark th {
          background-color: #1e293b; 
          color: #94a3b8; 
          font-weight: 600;
        }
        .table-dark td {
          border-color: #334155; 
        }
        .table-dark tr:nth-child(even) {
          background-color: #111827; 
        }
        .table-dark tr:hover {
          background-color: #334155 !important; 
        }
        .centered-heading {
            text-align: center;
            width: 100%;
            font-size: 1.5rem; 
            font-weight: 800; 
            line-height: 1.2;
            padding-bottom: 0.5rem;
        }
        .nav-btn-center {
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center; 
            min-height: 50px;
            padding: 0.75rem 1.5rem;
            line-height: 1.2;
            border-radius: 0.75rem;
        }
        
        /* JUDUL PUTIH SOLID */
        .text-solid-white {
            color: #ffffff; 
            text-shadow: none; 
        }
        
        /* --- STYLE BARU UNTUK CEK KUOTA RESULT --- */
        .result-success {
          background-color: #1f2937; /* Darker background */
          border: 1px solid #66b5e8; /* Accent blue border */
          color: #ffffff;
          box-shadow: 0 0 15px rgba(102, 181, 232, 0.4); /* Blue glow */
          transition: all 0.3s ease;
        }
        .result-error {
          background-color: #1f2937; /* Darker background */
          border: 1px solid #a466e8; /* Accent purple border */
          color: #ffffff;
          box-shadow: 0 0 15px rgba(164, 102, 232, 0.4); /* Purple glow */
          transition: all 0.3s ease;
        }
        
        /* Loading Spinner */
        #cover-spin {
          position: fixed;
          width: 100%;
          height: 100%;
          background-color: rgba(0,0,0,0.8);
          z-index: 9999;
          display: none;
        }
        .loader {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          border: 6px solid #f3f3f3;
          border-top: 6px solid var(--tw-color-accent-blue);
          border-radius: 50%;
          width: 50px;
          height: 50px;
          animation: spin 2s linear infinite;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        
        
      </style>
      
      
      
</head>
<body
    class="bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-white bg-fixed transition-colors duration-300"
  >
    <div
      id="loading-screen"
      class="fixed inset-0 z-50 flex justify-center items-center bg-gray-900 bg-opacity-80 transition-opacity duration-500"
    >
      <div
        class="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-400"
      ></div>
    </div>

    <div id="notification-badge" class="fixed z-50 opacity-0 transition-opacity ease-in-out duration-300 mt-9 mr-6 right-0 p-4 max-w-sm rounded-xl flex items-center gap-x-4 shadow-lg glass-effect dark:glass-effect-light">
        <div class="shrink-0">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6 text-accent-cyan">
                <path d="M5.85 3.5a.75.75 0 0 0-1.117-1 9.719 9.719 0 0 0-2.348 4.876.75.75 0 0 0 1.479.248A8.219 8.219 0 0 1 5.85 3.5ZM19.267 2.5a.75.75 0 1 0-1.118 1 8.22 8.22 0 0 1 1.987 4.124.75.75 0 0 0 1.48-.248A9.72 9.72 0 0 0 19.266 2.5Z" />
                <path fill-rule="evenodd" d="M12 2.25A6.75 6.75 0 0 0 5.25 9v.75a8.217 8.217 0 0 1-2.119 5.52.75.75 0 0 0 .298 1.206c1.544.57 3.16.99 4.831 1.243a3.75 3.75 0 1 0 7.48 0 24.583 24.583 0 0 0 4.83-1.244.75.75 0 0 0 .298-1.205 8.217 8.217 0 0 1-2.118-5.52V9A6.75 6.75 0 0 0 12 2.25ZM9.75 18c0-.034 0-.067.002-.1a25.05 25.05 0 0 0 4.496 0l.002.1a2.25 2.25 0 1 1-4.5 0Z" clip-rule="evenodd" />
            </svg>
        </div>
        <div>
            <div class="text-md font-bold text-accent-cyan">Berhasil!</div>
            <p class="text-sm text-gray-300">Akun berhasil disalin</p>
        </div>
    </div>

    <div class="flex flex-col items-center min-h-screen relative z-10 p-4">
  <div class="glass-effect-light dark:glass-effect w-full mb-6 rounded-xl p-4 shadow-lg">
    <div class="flex flex-wrap items-center justify-center gap-3 text-sm font-semibold">

      <p id="container-info-ip" class="flex items-center gap-1 text-blue-500 dark:text-blue-300">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
          <path d="M5.5 13a4.5 4.5 0 011.692-3.377l1.72-1.725A4.5 4.5 0 0113 5.5V6a.5.5 0 001 0V5.5A4.5 4.5 0 009.377 2.308L7.653 4.032A4.5 4.5 0 005 8.5v.5a.5.5 0 001 0V8.5A3.5 3.5 0 017.377 5.79l.995.996a.5.5 0 00.707-.707l-.996-.995A4.5 4.5 0 008.5 2.5a.5.5 0 000-1z" />
        </svg>
        IP: <span class="font-bold text-slate-800 dark:text-white">127.0.0.1</span>
      </p>
      <p id="container-info-country" class="flex items-center gap-1 text-green-500 dark:text-green-300">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 3.126A8.024 8.024 0 0110 3a8 8 0 01.445.126l.01.004.013.006.015.008A5.96 5.96 0 0014 9a6 6 0 01-5.995 5.986L9 15a6 6 0 01-5.986-5.995l-.004-.01-.006-.013A6.024 6.024 0 013 10a8.024 8.024 0 01.126-.445l.004-.01.006-.013.008-.015A5.96 5.96 0 009 6a6 6 0 015.995 5.986L15 12a6 6 0 01-5.986 5.995l-.01-.004-.013-.006-.015-.008A6.024 6.024 0 019 18z" clip-rule="evenodd" />
        </svg>
        Country: <span class="font-bold text-slate-800 dark:text-white">Singapore</span>
      </p>
      <p id="container-info-isp" class="flex items-center gap-1 text-indigo-500 dark:text-indigo-300">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
          <path d="M10 3a7 7 0 00-7 7h1.5a5.5 5.5 0 1111 0h1.5a7 7 0 00-7-7z" />
        </svg>
        ISP: <span class="font-bold text-slate-800 dark:text-white">Localhost</span>
      </p>

      <p class="flex items-center gap-1 text-purple-500 dark:text-purple-300">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
          <path d="M3 3a1 1 0 00-1 1v12a1 1 0 001 1h14a1 1 0 001-1V4a1 1 0 00-1-1H3zm13 2H4v10h12V5z" />
        </svg>
        <span class="text-gray-600 dark:text-gray-300">Total Proxy: <strong id="total-proxy-value" class="font-semibold">0</strong></span>
      </p>
      <p class="flex items-center gap-1 text-orange-500 dark:text-orange-300">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M3 6a2 2 0 012-2h10a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V6zm2 2a1 1 0 00-1 1v4a1 1 0 001 1h10a1 1 0 001-1V9a1 1 0 00-1-1H5zm1 2h2v2H6v-2zm4 0h2v2h-2v-2z" clip-rule="evenodd" />
        </svg>
        <span class="text-gray-600 dark:text-gray-300">Page: <strong id="page-info-value" class="font-semibold">0/0</strong></span>
      </p>
      <p class="flex items-center gap-1 text-teal-500 dark:text-teal-300">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd" />
        </svg>
        Time: <strong id="time-info-value" class="font-semibold text-slate-800 dark:text-white">00:00:00</strong>
      </p>
    </div>
    <div class="mt-4 flex gap-2">
        <input type="text" id="search-bar" placeholder="Search by IP, Port, ISP, or Country..." class="w-full px-4 py-1 rounded-lg bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500">
        <button onclick="searchProxy()" class="text-white px-4 py-1 rounded text-sm font-semibold transition-colors duration-200 action-btn">Search</button>
    </div>
  </div>

  <div id="container-title" class="sticky top-0 z-10 w-full max-w-7xl rounded-xl py-6 text-center shadow-lg backdrop-blur-md transition-all duration-300 ease-in-out">
    <h1 id="runningTitle" class="text-3xl font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-purple-500 to-pink-500 animate-pulse">
      PLACEHOLDER_JUDUL
    </h1>
  </div>

  <div class="w-full max-w-5xl mb-8 p-6 bg-gray-800 rounded-xl shadow-xl grid grid-cols-2 md:grid-cols-4 gap-4" style="box-shadow: 0 4px 15px rgba(0,0,0,0.5), inset 0 0 10px rgba(0,0,0,0.2);">
        PLACEHOLDER_PROTOCOL_DROPDOWN
        PLACEHOLDER_COUNTRY_DROPDOWN
        PLACEHOLDER_HOST_DROPDOWN
        PLACEHOLDER_PORT_DROPDOWN
    </div>

  <div class="flex flex-col md:flex-row gap-4 pt-8 w-full max-w-7xl justify-center">
    PLACEHOLDER_PROXY_GROUP
  </div>

        <!-- Pagination -->
        <nav id="container-pagination" class="w-full max-w-7xl mt-8 sticky bottom-2 z-20 transition-transform -translate-y-6 flex flex-col items-center">
            <ul class="flex justify-center space-x-2">
                PLACEHOLDER_PAGE_BUTTON
            </ul>
            <p class="text-sm text-gray-600 dark:text-gray-400 mt-4">PLACEHOLDER_PAGINATION_INFO</p>
        </nav>
    </div>

    <div id="container-window" class="hidden">
  <div class="fixed z-20 top-0 inset-0 w-full h-full bg-gray-900/80 backdrop-blur-sm flex justify-center items-center animate-fade-in">
    <p id="container-window-info" class="text-center w-full h-full top-1/4 absolute text-white animate-pulse"></p>
  </div>

  <div id="output-window" class="fixed z-30 inset-0 flex justify-center items-center p-2 hidden">
    <div class="w-full max-w-xs flex flex-col gap-2 p-4 text-center rounded-xl bg-gray-800 border border-gray-700 shadow-lg animate-zoom-in">

      <div class="flex flex-col items-center gap-1 mb-1">
        <h4 class="text-xl font-bold text-white mt-1">Pilih Format</h4>
        </div>

      <div class="grid grid-cols-2 gap-1">
    <button onclick="copyToClipboardAsTarget('clash')" class="p-1.5 rounded-md bg-sky-500 hover:bg-sky-600 text-xs font-semibold text-white flex flex-col justify-center items-center transition-transform transform hover:scale-105 shadow-sm">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 512" fill="currentColor" class="size-5 mb-0.5"><path d="M479.9 32.1C479.9 14.46 465.4 0 448 0H192c-17.47 0-32.22 14.46-31.99 31.99L160 384c0 17.46 14.46 32 32 32h128l-32.99 95.82c-4.141 12.19 2.594 25.75 14.78 29.89C304.8 512.9 308.8 512 312.4 512c8.203 0 16.28-4.484 20.78-12.14l128-224C474.7 269.8 480 263.2 480 256v-224C480 29.8 479.9 32.1 479.9 32.1zM384 256L272 448l64.01-192.1c.1406-.4375 .2812-.875 .4375-1.312L384 256z"/></svg>
        Clash
    </button>
    <button onclick="copyToClipboardAsTarget('sfa')" class="p-1.5 rounded-md bg-sky-500 hover:bg-sky-600 text-xs font-semibold text-white flex flex-col justify-center items-center transition-transform transform hover:scale-105 shadow-sm">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 576 512" fill="currentColor" class="size-5 mb-0.5"><path d="M576 128c0-35.3-28.7-64-64-64h-38.3c-1.6 4.6-3.7 9-6.4 13.1l-10.4 15.6c-20.7 31.1-55.1 52.4-94.8 55.9c-29.5 2.6-58.8-3.4-86.3-17.8c-23.7-12.2-46.3-25.9-63.5-39.7c-5.9-4.7-12.8-8-20.3-9.9L160.8 64H112C76.75 64 48 92.75 48 128c0 35.25 28.75 64 64 64H172.5c20.3-10.8 42.6-17.7 65.5-20.5c10.5-1.2 21.1-1.7 31.8-1.7c-11 5.9-21.4 13.5-30.8 22.8c-20.6 20.5-35.3 45.4-42.5 73.6c-1.3 5.3-2 10.9-2 16.6c0 10.6 2 20.9 6.2 30.6c3.2 7.6 7.6 15 13 22.1c25.4 33.3 59 55 96.6 63.8c-1.6 2.1-3.2 4.1-4.9 6.1c-14.7 17.5-30.7 33.2-47.5 46.9c-7.9 6.5-16.1 12.3-24.6 17.2c-29.1 16.9-59.5 28.7-90.9 35.3c-11.6 2.5-23.3 3.8-35 3.8h-48.4c-12.3 0-24.2-4.1-34.6-11.5L5.6 422.3c-13.8-10.1-2.9-31.2 14.8-28.7c18.5 2.6 37.1 3.9 55.7 3.9c25.3 0 50.8-3.4 75.8-10.3c15.2-4.3 30.1-9.9 44.5-16.9c13.7-6.7 26.9-14.7 39.5-24.1c11.9-8.9 23.3-18.7 34.3-29.5c14.7-14.6 27.6-30.6 38.3-48.4c7-11.8 12.8-24.5 17.1-37.6c1.6-4.9 2.8-10 3.8-15c1-5.1 1.5-10.3 1.5-15.6c0-14.7-2.9-29.3-8.6-43.2c-5.8-14.2-13.8-27.7-23.8-40.2c-1.4-1.7-2.9-3.4-4.5-5.1c4.5-3.3 9.4-5.6 14.6-6.8c12.2-2.9 24.6-4.3 37.1-4.3c27.5 0 54.9 5.8 80.8 17.1c26.1 11.4 49.6 27.9 69.8 49.3c15.9 17 28.3 36.3 37.4 57.6c9.1 21.2 14.2 44.1 15.1 67.2c1.7 44.5-13.1 87.8-42.5 122.9c-29.4 35.1-69.6 57.9-114.7 63.8c-1.7 .2-3.4 .3-5.1 .5c-1.3 .2-2.5 .5-3.8 .6l-149.3 46.6c-13.3 4.1-27.1 6.1-40.9 6.1c-17.7 0-35.3-2.5-52.5-7.5l-63.5-18.4c-12.7-3.7-25.5-5.5-38.3-5.5c-35.3 0-64 28.7-64 64s28.7 64 64 64H112c35.25 0 64-28.75 64-64V448h145c11.3 0 22.6-1.5 33.9-4.5c44.8-11.9 84.1-39.2 114.6-77.9c30.3-38.6 47.9-86.8 48.9-136.5c1.4-71.9-28.7-142.1-85-189.6c-1.1-1-2.2-2.1-3.4-3.1c-14.1-12.3-30.8-22.3-49.3-29.5c-1.6-.6-3.1-1.3-4.7-1.9c-1.7-.6-3.4-1.1-5.1-1.5z"/></svg>
        SFA
    </button>
    <button onclick="copyToClipboardAsTarget('bfr')" class="p-1.5 rounded-md bg-sky-500 hover:bg-sky-600 text-xs font-semibold text-white flex flex-col justify-center items-center transition-transform transform hover:scale-105 shadow-sm">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" fill="currentColor" class="size-5 mb-0.5"><path d="M464 256A208 208 0 1 0 48 256a208 208 0 1 0 416 0zM0 256a256 256 0 1 1 512 0A256 256 0 1 1 0 256zm288 32c0-11.5 6.1-22 16-27.6l80-45.7c10.8-6.2 24.3-3.4 31.5 6.9s3.2 23.4-7.5 29.7l-80 45.7c-2.4 1.4-5 2.2-7.8 2.2s-5.4-.8-7.8-2.2l-128-73.1c-10.8-6.2-13.6-19.7-7.5-30.5s19.7-13.6 30.5-7.5L256 226.4V64c0-17.7 14.3-32 32-32s32 14.3 32 32v240c0 17.7-14.3 32-32 32s-32-14.3-32-32v-44.5l-80 45.7c-10.8 6.2-13.6 19.7-7.5 30.5s19.7 13.6 30.5 7.5L256 280.9V448c0 17.7-14.3 32-32 32s-32-14.3-32-32V208c0-11.5-6.1-22-16-27.6L96 134.7c-10.8-6.2-24.3-3.4-31.5 6.9s-3.2 23.4 7.5 29.7l80 45.7c2.4 1.4 5 2.2 7.8 2.2s5.4-.8 7.8-2.2l128-73.1c10.8-6.2 13.6-19.7 7.5-30.5s-19.7-13.6-30.5-7.5L256 167.1V288z"/></svg>
        BFR
    </button>
    <button onclick="copyToClipboardAsRaw()" class="p-1.5 rounded-md bg-gray-400 hover:bg-gray-500 text-xs font-semibold text-white flex flex-col justify-center items-center transition-transform transform hover:scale-105 shadow-sm">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 576 512" fill="currentColor" class="size-5 mb-0.5"><path d="M471.6 31.84c-3.641-4.22-8.527-6.552-13.69-6.552h-384c-5.164 0-10.05 2.332-13.69 6.552c-3.641 4.22-5.11 9.771-4.264 15.22l23.11 150.9C69.45 204.4 74.52 208 80 208h416c5.473 0 10.55-3.606 11.85-8.001l23.11-150.9C524.8 41.61 523.3 36.06 519.6 31.84zM240 336c0-8.836 7.164-16 16-16h64c8.836 0 16 7.164 16 16v160c0 8.836-7.164 16-16 16h-64c-8.836 0-16-7.164-16-16V336zM320 224c-8.836 0-16-7.164-16-16s7.164-16 16-16h64c8.836 0 16 7.164 16 16s-7.164 16-16 16h-64zM224 224h-64c-8.836 0-16-7.164-16-16s7.164-16 16-16h64c8.836 0 16 7.164 16 16S232.8 224 224 224zM416 336c0-8.836 7.164-16 16-16h64c8.836 0 16 7.164 16 16v160c0 8.836-7.164 16-16 16h-64c-8.836 0-16-7.164-16-16V336zM160 336c0-8.836 7.164-16 16-16h64c8.836 0 16 7.164 16 16v160c0 8.836-7.164 16-16 16h-64c-8.836 0-16-7.164-16-16V336z"/></svg>
        Raw
    </button>
</div>

<div class="flex justify-center">
  <button onclick="toggleOutputWindow()" class="mt-1 p-3 rounded-lg bg-red-500 hover:bg-red-600 text-xs text-white font-semibold transition-colors duration-300 flex items-center justify-center gap-1">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 384 512" fill="currentColor" class="size-3">
          <path d="M342.6 150.6c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0L192 210.7 86.6 105.4c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3L146.7 256 41.4 361.4c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L192 301.3 297.4 406.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3L237.3 256 342.6 150.6z"/>
      </svg>
      Close
  </button>
</div>
    </div>
  </div>
</div>
</div>
      <!-- Wildcards -->
      <div id="wildcards-window" class="fixed hidden z-30 top-0 right-0 w-full h-full flex justify-center items-center">
    <div class="w-[75%] max-w-md h-auto flex flex-col gap-2 p-4 rounded-lg bg-white bg-opacity-20 backdrop-blur-sm border border-gray-300">
        <div class="flex w-full h-full gap-2 justify-between">
            <input id="new-domain-input" type="text" placeholder="Input wildcard" class="w-full h-full px-4 py-2 rounded-md focus:outline-0 bg-gray-700 text-white"/>
            <button onclick="registerDomain()" class="p-2 rounded-full bg-blue-600 hover:bg-blue-700 flex justify-center items-center">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6">
                    <path fill-rule="evenodd" d="M16.72 7.72a.75.75 0 0 1 1.06 0l3.75 3.75a.75.75 0 0 1 0 1.06l-3.75 3.75a.75.75 0 1 1-1.06-1.06l2.47-2.47H3a.75.75 0 0 1 0-1.5h16.19l-2.47-2.47a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd"></path>
                </svg>
            </button>
        </div>

        <div id="container-domains" class="w-full h-32 rounded-md flex flex-col gap-1 overflow-y-scroll scrollbar-hide p-2 bg-gray-900"></div>

        <button onclick="toggleWildcardsWindow()" class="transform-gpu flex items-center justify-center gap-1 rounded-xl bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white text-sm font-medium shadow-lg hover:shadow-blue-500/30 transition-all duration-200 hover:-translate-y-0.5 p-2">
    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
        <path fill-rule="evenodd" d="M5.47 5.47a.75.75 0 011.06 0L12 10.94l5.47-5.47a.75.75 0 111.06 1.06L13.06 12l5.47 5.47a.75.75 0 11-1.06 1.06L12 13.06l-5.47 5.47a.75.75 0 01-1.06-1.06L10.94 12 5.47 6.53a.75.75 0 010-1.06z" clip-rule="evenodd"/>
    </svg>
    Close
</button>
    </div>
</div>
    </div>

    <footer>
    <div class="fixed bottom-4 right-4 flex flex-col items-end gap-3 z-50">
        <button onclick="toggleDropdown()" class="transition-colors rounded-full p-2 block text-white shadow-lg transform hover:scale-105 bg-accent-blue hover:bg-opacity-80">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6 text-white">
                <path d="M12 2.25a.75.75 0 0 1 .75.75v6.75h6.75a.75.75 0 0 1 0 1.5h-6.75v6.75a.75.75 0 0 1-1.5 0v-6.75h-6.75a.75.75 0 0 1 0-1.5h6.75V3a.75.75 0 0 1 .75-.75Z" clip-rule="evenodd" />
            </svg>
        </button>

        <div id="dropdown-menu" class="hidden flex flex-col gap-3">
            <a href="PLACEHOLDER_DONATE_LINK" target="_blank">
                <button class="bg-accent-cyan hover:bg-teal-600 rounded-full border-2 border-gray-900 p-2 block transition-colors duration-200">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6">
                        <path d="M10.464 8.746c.227-.18.497-.311.786-.394v2.795a2.252 2.252 0 0 1-.786-.393c-.394-.313-.546-.681-.546-1.004 0-.323.152-.691.546-1.004ZM12.75 15.662v-2.824c.347.085.664.228.921.421.427.32.579.686.579.991 0 .305-.152.671-.579.991a2.534 2.534 0 0 1-.921.42Z" />
                        <path fill-rule="evenodd" d="M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25ZM12.75 6a.75.75 0 0 0-1.5 0v.816a3.836 3.836 0 0 0-1.72.756c-.712.566-1.112 1.35-1.112 2.178 0 .829.4 1.612 1.113 2.178.502.4 1.102.647 1.719.756v2.978a2.536 2.536 0 0 1-.921-.421l-.879-.66a.75.75 0 0 0-.9 1.2l.879.66c.533.4 1.169.645 1.821.75V18a.75.75 0 0 0 1.5 0v-.81a4.124 4.124 0 0 0 1.821-.749c.745-.559 1.179-1.344 1.179-2.191 0-.847-.434-1.632-1.179-2.191a4.122 4.122 0 0 0-1.821-.75V8.354c.29.082.559.213.786.393l.415.33a.75.75 0 0 0 .933-1.175l-.415-.33a3.836 3.836 0 0 0-1.719-.755V6Z" clip-rule="evenodd" />
                    </svg>
                </button>
            </a>

            PLACEHOLDER_WHATSAPP_BUTTON

            PLACEHOLDER_TELEGRAM_BUTTON
            
            <button onclick="toggleWildcardsWindow()" class="bg-indigo-500 hover:bg-indigo-600 rounded-full border-2 border-gray-900 p-2 transition-colors duration-200">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 9V4.5M9 9H4.5M9 9 3.75 3.75M9 15v4.5M9 15H4.5M9 15l-5.25 5.25M15 9h4.5M15 9V4.5M15 9l5.25-5.25M15 15h4.5M15 15v4.5m0-4.5 5.25 5.25" />
                </svg>
            </button>

            <button onclick="toggleDarkMode()" class="bg-amber-500 hover:bg-amber-600 rounded-full border-2 border-gray-900 p-2 transition-colors duration-200">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" />
                </svg>
            </button>
        </div>
    </div>
</footer>
<script>
    function toggleDropdown() {
        const dropdownMenu = document.getElementById('dropdown-menu');
        dropdownMenu.classList.toggle('hidden');
    }
</script>

<script>
    document.addEventListener('DOMContentLoaded', () => {
    const runningTitle = document.getElementById('runningTitle');
    const container = runningTitle.parentElement;
    let position = -runningTitle.offsetWidth; // Mulai dari luar kiri
    const speed = 1.5; // Kecepatan pergerakan

    function animateTitle() {
        position += speed;

        // Jika teks sudah melewati container, kembalikan ke posisi awal
        if (position > container.offsetWidth) {
            position = -runningTitle.offsetWidth;
        }

        // PERBAIKAN: Menggabungkan string dan variabel dengan tanda '+'
        runningTitle.style.transform = 'translateX(' + position + 'px)';

        requestAnimationFrame(animateTitle);
    }

    animateTitle();
});
</script>


     <script>
  document.addEventListener('DOMContentLoaded', function() {
    const loadingScreen = document.getElementById('loading-screen');
    if (loadingScreen) {
      // Tunggu 5 detik sebelum memulai transisi
      setTimeout(() => {
        // Atur opacity menjadi 0 untuk memulai efek fade out
        loadingScreen.style.opacity = '0';
        
        // Setelah efek fade out selesai (500ms), sembunyikan elemen
        setTimeout(() => {
          loadingScreen.style.display = 'none';
        }, 500); // Durasi ini harus sama dengan durasi transisi di CSS (duration-500)
      }, 1000); // <-- Ini adalah jeda 5 detik
    }
  });
    
      // Shared
      const rootDomain = "PLACEHOLDER_ROOT_DOMAIN";
      const notification = document.getElementById("notification-badge");
      const windowContainer = document.getElementById("container-window");
      const windowInfoContainer = document.getElementById("container-window-info");


      // Switches
      let isDomainListFetched = false;

      // Local variable
      let rawConfig = "";

      function getDomainList() {
        if (isDomainListFetched) return;
        isDomainListFetched = true;

        windowInfoContainer.innerText = "Fetching data...";

        const url = "https://" + rootDomain + "/api/v1/domains/get";
        fetch(url).then(async (res) => {
          const domainListContainer = document.getElementById("container-domains");
          domainListContainer.innerHTML = "";

          if (res.status == 200) {
            windowInfoContainer.innerText = "Done!";
            const respJson = await res.json();
            respJson.forEach((domain, index) => {
              const domainContainer = document.createElement("div");
              domainContainer.className = "flex items-center justify-between w-full bg-amber-400 rounded-md p-2";

              const domainText = document.createElement("span");
              domainText.innerText = (index + 1) + ". " + domain.hostname;
              domainContainer.appendChild(domainText);

              const deleteButton = document.createElement("button");
              deleteButton.innerText = "Hapus";
              deleteButton.className = "bg-red-500 hover:bg-red-600 text-white font-bold py-1 px-2 rounded text-xs";
              deleteButton.onclick = () => deleteDomain(domain.id, domain.hostname);
              domainContainer.appendChild(deleteButton);

              domainListContainer.appendChild(domainContainer);
            });
          } else {
            windowInfoContainer.innerText = "Failed!";
          }
        });
      }

      function deleteDomain(domainId, domainName) {
        Swal.fire({
          title: 'Masukkan Password',
          text: "Untuk menghapus domain: " + domainName,
          input: 'password',
          inputPlaceholder: 'Password...',
          inputAttributes: {
            autocapitalize: 'off'
          },
          showCancelButton: true,
          confirmButtonText: 'Hapus',
          cancelButtonText: 'Batal',
          width: '300px',
          showLoaderOnConfirm: true,
          preConfirm: (password) => {
            if (!password) {
              Swal.showValidationMessage('Password tidak boleh kosong');
              return false;
            }
            const url = "https://" + rootDomain + "/api/v1/domains/delete?id=" + domainId + "&password=" + encodeURIComponent(password);
            return fetch(url, { method: 'DELETE' })
              .then(response => {
                if (!response.ok) {
                    if (response.status === 401) {
                        throw new Error("Password salah!");
                    }
                    throw new Error("Gagal! Status: " + response.status);
                }
                return response.json().catch(() => ({}));
              })
              .catch(error => {
                Swal.showValidationMessage(error.message);
                return false;
              });
          },
          allowOutsideClick: () => !Swal.isLoading()
        }).then((result) => {
          if (result.isConfirmed) {
             Swal.fire({
                title: 'Berhasil!',
                text: 'Domain telah dihapus.',
                icon: 'success',
                width: '300px',
                timer: 1500,
                showConfirmButton: false
             });
            isDomainListFetched = false;
            getDomainList();
          }
        });
      }

      function registerDomain() {
        const domainInputElement = document.getElementById("new-domain-input");
        const rawDomain = domainInputElement.value.toLowerCase();
        const domain = domainInputElement.value + "." + rootDomain;

        if (!rawDomain.match(/\\w+\\.\\w+$/) || rawDomain.endsWith(rootDomain)) {
          windowInfoContainer.innerText = "Invalid URL!";
          return;
        }

        windowInfoContainer.innerText = "Pushing request...";

        const url = "https://" + rootDomain + "/api/v1/domains/put?domain=" + domain;
        const res = fetch(url).then((res) => {
          if (res.status == 200) {
            windowInfoContainer.innerText = "Done!";
            domainInputElement.value = "";
            isDomainListFetched = false;
            getDomainList();
          } else {
            if (res.status == 409) {
              windowInfoContainer.innerText = "Domain exists!";
            } else {
              windowInfoContainer.innerText = "Error " + res.status;
            }
          }
        });
      }

      function copyToClipboard(text) {
        toggleOutputWindow();
        rawConfig = text;
      }

      function copyToClipboardAsRaw() {
        navigator.clipboard.writeText(rawConfig);

        notification.classList.remove("opacity-0");
        setTimeout(() => {
          notification.classList.add("opacity-0");
        }, 2000);
      }

      async function copyToClipboardAsTarget(target) {
        windowInfoContainer.innerText = "Generating config...";
        const url = "PLACEHOLDER_CONVERTER_URL";
        const res = await fetch(url, {
          method: "POST",
          body: JSON.stringify({
            url: rawConfig,
            format: target,
            template: "cf",
          }),
        });

        if (res.status == 200) {
          windowInfoContainer.innerText = "Done!";
          navigator.clipboard.writeText(await res.text());

          notification.classList.remove("opacity-0");
          setTimeout(() => {
            notification.classList.add("opacity-0");
          }, 2000);
        } else {
          windowInfoContainer.innerText = "Error " + res.statusText;
        }
      }

      function navigateTo(link) {
        window.location.href = link + window.location.search;
      }

      function applyFilters() {
          const protocol = document.getElementById('protocol-select').value;
          const country = document.getElementById('country-select').value;
          const host = document.getElementById('host-select').value;
          const port = document.getElementById('port-select').value;

          const url = new URL(window.location.href);
          url.searchParams.set('vpn', protocol);
          url.searchParams.set('cc', country);
          url.searchParams.set('host', host);
          url.searchParams.set('port', port);
          window.location.href = url.toString();
      }

      function searchProxy() {
        const searchBar = document.getElementById("search-bar");
        const searchValue = searchBar.value;
        const url = new URL(window.location.href);
        if (searchValue.length === 2) {
          url.searchParams.set("cc", searchValue);
          url.searchParams.delete("search");
        } else {
          url.searchParams.set("search", searchValue);
          url.searchParams.delete("cc");
        }
        window.location.href = url.toString();
      }

      function toggleOutputWindow() {
        windowInfoContainer.innerText = "Select output:";
        toggleWindow();
        const rootElement = document.getElementById("output-window");
        if (rootElement.classList.contains("hidden")) {
          rootElement.classList.remove("hidden");
        } else {
          rootElement.classList.add("hidden");
        }
      }

      function toggleWildcardsWindow() {
        windowInfoContainer.innerText = "Domain list";
        toggleWindow();
        getDomainList();
        const rootElement = document.getElementById("wildcards-window");
        if (rootElement.classList.contains("hidden")) {
          rootElement.classList.remove("hidden");
        } else {
          rootElement.classList.add("hidden");
        }
      }

      function toggleWindow() {
        if (windowContainer.classList.contains("hidden")) {
          windowContainer.classList.remove("hidden");
        } else {
          windowContainer.classList.add("hidden");
        }
      }

      function toggleDarkMode() {
        const rootElement = document.getElementById("html");
        if (rootElement.classList.contains("dark")) {
          rootElement.classList.remove("dark");
        } else {
          rootElement.classList.add("dark");
        }
      }

      function checkProxy() {
    for (let i = 0; ; i++) {
        const pingElement = document.getElementById("ping-" + i);
        if (pingElement == undefined) return;

        const target = pingElement.textContent.split(" ").filter((ipPort) => ipPort.match(":"))[0];
        if (target) {
            pingElement.textContent = "Checking...";
        } else {
            continue;
        }

        let isActive = false;
        new Promise(async (resolve) => {
            const res = await fetch('PLACEHOLDER_CHECK_PROXY_URL' + target)
                .then(async (res) => {
                    if (isActive) return;
                    if (res.status == 200) {
                        pingElement.classList.remove("dark:text-white");
                        const jsonResp = await res.json();
                        
                        // Periksa status dari JSON, bukan dari properti proxyip
                        if (jsonResp.status === "ACTIVE") {
                            isActive = true;
                            // Mengambil delay dan colo dari data JSON
                            const delay = jsonResp.delay || "N/A";
                            const colo = jsonResp.colo || "N/A";
                            pingElement.textContent = "Active " + delay + " (" + colo + ")";
                            pingElement.classList.add("text-green-600");
                            pingElement.classList.remove("text-red-600"); // Pastikan kelas lain dihapus
                        } else {
                            pingElement.textContent = "Inactive";
                            pingElement.classList.add("text-red-600");
                            pingElement.classList.remove("text-green-600"); // Pastikan kelas lain dihapus
                        }
                    } else {
                        pingElement.textContent = "Check Failed!";
                        pingElement.classList.add("text-red-600");
                        pingElement.classList.remove("text-green-600");
                    }
                })
                .finally(() => {
                    resolve(0);
                });
        });
    }
}

      function checkRegion() {
        for (let i = 0; ; i++) {
          const containerRegionCheck = document.getElementById("container-region-check-" + i);
          const configSample = document.getElementById("config-sample-" + i).value.replaceAll(" ", "");
          if (containerRegionCheck == undefined) break;

          const res = fetch(
            "https://api.foolvpn.me/regioncheck?config=" + encodeURIComponent(configSample)
          ).then(async (res) => {
            if (res.status == 200) {
              containerRegionCheck.innerHTML = "<hr>";
              for (const result of await res.json()) {
                containerRegionCheck.innerHTML += "<p>" + result.name + ": " + result.region + "</p>";
              }
            }
          });
        }
      }

      function checkGeoip() {
        const containerIP = document.getElementById("container-info-ip");
        const containerCountry = document.getElementById("container-info-country");
        const containerISP = document.getElementById("container-info-isp");
        const res = fetch("https://" + rootDomain + "/api/v1/myip").then(async (res) => {
          if (res.status == 200) {
            const respJson = await res.json();
            containerIP.innerText = "IP: " + respJson.ip;
            containerCountry.innerText = "Country: " + respJson.country;
            containerISP.innerText = "ISP: " + respJson.asOrganization;
          }
        });
      }

     function updateTime() {
    const timeElement = document.getElementById("time-info-value");
    if (timeElement) {
        const now = new Date();
        const timeString = now.toLocaleTimeString('en-GB');
        timeElement.textContent = timeString;
    }
}

setInterval(updateTime, 1000);

      window.onload = () => {
        checkGeoip();
        checkProxy();
        updateTime();
        // checkRegion();
        const observer = lozad(".lozad", {
          load: function (el) {
            el.classList.remove("scale-95");
          },
        });
        observer.observe();
      };

      window.onscroll = () => {
        const paginationContainer = document.getElementById("container-pagination");

        if (window.innerHeight + Math.round(window.scrollY) >= document.body.offsetHeight) {
          paginationContainer.classList.remove("-translate-y-6");
        } else {
          paginationContainer.classList.add("-translate-y-6");
        }
      };
    </script>
  </body>
</html>
`;

class Document {
    proxies = [];

    constructor(request) {
        this.html = baseHTML;
        this.request = request;
        this.url = new URL(this.request.url);
    }

    setTotalProxy(total) {
        this.html = this.html.replace(
            '<strong id="total-proxy-value" class="font-semibold">0</strong>',
            `<strong id="total-proxy-value" class="font-semibold">${total}</strong>`
        );
    }
    
    setPage(current, total) {
        this.html = this.html.replace(
            '<strong id="page-info-value" class="font-semibold">0/0</strong>',
            `<strong id="page-info-value" class="font-semibold">${current}/${total}</strong>`
        );
    }

setTitle(title) {
    this.html = this.html.replaceAll("PLACEHOLDER_JUDUL", title.replace("text-blue-500", "text-indigo-500"));
  }

  addInfo(text) {
    text = `<span>${text}</span>`;
    this.html = this.html.replaceAll("PLACEHOLDER_INFO", `${text}\nPLACEHOLDER_INFO`);
  }

    registerProxies(data, proxies) {
        this.proxies.push({
            ...data,
            list: proxies,
        });
    }

    buildProxyGroup() {
        let tableRows = "";
        for (let i = 0; i < this.proxies.length; i++) {
            const prx = this.proxies[i];
            const proxyConfigs = prx.list.join(',');
            tableRows += `
                <tr class="border-t border-gray-700 hover:bg-gray-800">
    <td class="px-3 py-3 text-base text-gray-400 text-center">${i + 1}</td>
    <td class="px-3 py-3 text-base font-mono text-center">${prx.prxIP}</td>
    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300 flex items-center justify-center">
        <img src="https://hatscripts.github.io/circle-flags/flags/${prx.country.toLowerCase()}.svg" width="20" class="inline mr-2 rounded-full"/>
        ${prx.country}
    </td>
    <td class="px-3 py-3 text-base truncate max-w-[150px] text-center">${prx.org}</td>
    <td id="ping-${i}" class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-white text-center">${prx.prxIP}:${prx.prxPort}</td>
    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-center">
        <button onclick="copyToClipboard('${proxyConfigs}')" class="text-white px-4 py-1 rounded text-sm font-semibold transition-colors duration-200 action-btn">Copy</button>
    </td>
</tr>
            `;
        }

        const table = `
            <div class="overflow-x-auto w-full max-w-full">
            <table class="min-w-full table-dark bg-gray-800 border border-gray-700 rounded-xl text-base overflow-hidden" style="box-shadow: 0 4px 10px rgba(0,0,0,0.3);">
                <thead>
                    <tr class="text-gray-400">
                            <th class="px-3 py-3 text-center">No.</th>
                            <th class="px-3 py-3 text-center">IP</th>
                            <th class="px-3 py-3 text-center">Country</th>
                            <th class="px-3 py-3 text-center">ISP</th>
                            <th class="px-3 py-3 text-center">Status</th>
                            <th class="px-3 py-3 text-center">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${tableRows}
                    </tbody>
                </table>
            </div>
        `;

        this.html = this.html.replaceAll("PLACEHOLDER_PROXY_GROUP", table);
    }

    buildCountryFlag() {
        const prxBankUrl = this.url.searchParams.get("prx-list");
        const selectedCC = this.url.searchParams.get("cc");
        const flagList = [];
        for (const proxy of cachedPrxList) {
            flagList.push(proxy.country);
        }

        let flagElement = "";
        for (const flag of new Set(flagList)) {
            const isSelected = selectedCC === flag;
            // Apply different classes based on selection state
            const linkClasses = isSelected 
                ? 'border-2 border-blue-400 rounded-lg p-0.5' // Classes for selected flag
                : 'py-1';                                     // Classes for non-selected flag

            flagElement += `<a href="/sub?cc=${flag}${prxBankUrl ? "&prx-list=" + prxBankUrl : ""
                }" class="flex items-center justify-center ${linkClasses}" ><img width=30 src="https://hatscripts.github.io/circle-flags/flags/${flag.toLowerCase()}.svg" /></a>`;
        }

        this.html = this.html.replaceAll("PLACEHOLDER_BENDERA_NEGARA", flagElement);
    }

    addPageButton(text, link, isDisabled) {
        const pageButton = `<li><button ${
            isDisabled ? "disabled" : ""
        } class="px-6 py-2 text-white rounded-lg disabled:opacity-50 text-base font-semibold btn-gradient hover:opacity-80 transition-opacity" onclick=navigateTo('${link}')>${text}</button></li>`;

        this.html = this.html.replaceAll("PLACEHOLDER_PAGE_BUTTON", `${pageButton}\nPLACEHOLDER_PAGE_BUTTON`);
    }


    setPaginationInfo(info) {
        this.html = this.html.replace("PLACEHOLDER_PAGINATION_INFO", info);
    }

    build() {
        this.buildProxyGroup();
        this.buildCountryFlag();

        this.html = this.html.replaceAll("PLACEHOLDER_API_READY", isApiReady ? "block" : "hidden");

        let whatsappButton = '';
        if (WHATSAPP_NUMBER) {
            whatsappButton = `<a href="https://wa.me/${WHATSAPP_NUMBER}" target="_blank">
                              <button class="bg-green-500 hover:bg-green-600 rounded-full border-2 border-gray-900 p-2 block transition-colors duration-200">
                                <img src="https://geoproject.biz.id/circle-flags/whatsapp.png" alt="WhatsApp Icon" class="size-6">
                              </button>
                            </a>`;
        }
        this.html = this.html.replace('PLACEHOLDER_WHATSAPP_BUTTON', whatsappButton);

        let telegramButton = '';
        if (TELEGRAM_USERNAME) {
            telegramButton = `<a href="https://t.me/${TELEGRAM_USERNAME}" target="_blank">
                              <button class="bg-blue-500 hover:bg-blue-600 rounded-full border-2 border-gray-900 p-2 block transition-colors duration-200">
                                <img src="https://geoproject.biz.id/circle-flags/telegram.png" alt="Telegram Icon" class="size-6">
                              </button>
                            </a>`;
        }
        this.html = this.html.replace('PLACEHOLDER_TELEGRAM_BUTTON', telegramButton);

        this.html = this.html.replaceAll('PLACEHOLDER_CHECK_PROXY_URL', `https://${serviceName}.${rootDomain}/check?target=`);
        this.html = this.html.replaceAll('PLACEHOLDER_ROOT_DOMAIN', `${serviceName}.${rootDomain}`);
        this.html = this.html.replaceAll('PLACEHOLDER_CONVERTER_URL', CONVERTER_URL);
        this.html = this.html.replaceAll('PLACEHOLDER_DONATE_LINK', DONATE_LINK);

        this.buildDropdowns();

        return this.html.replaceAll(/PLACEHOLDER_\w+/gim, "");
    }

    buildDropdowns() {
        const selectedProtocol = this.url.searchParams.get('vpn') || 'all';
        const selectedCountry = this.url.searchParams.get('cc') || 'all';
        const selectedHost = this.url.searchParams.get('host') || APP_DOMAIN;
        const selectedPort = this.url.searchParams.get('port') || 'all';

        // Protocol Dropdown
        const protocols = [{
            value: 'all',
            label: 'All Protocols'
        }, {
            value: 'vless',
            label: 'VLESS'
        }, {
            value: 'trojan',
            label: 'TROJAN'
        }, {
            value: 'ss',
            label: 'SHADOWSOCKS'
        }];
        let protocolOptions = '';
        for (const proto of protocols) {
            protocolOptions += `<option value="${proto.value}" ${selectedProtocol === proto.value ? 'selected' : ''}>${proto.label}</option>`;
        }
        this.html = this.html.replace('PLACEHOLDER_PROTOCOL_DROPDOWN', `
            <div class="relative">
                <label for="protocol-select" class="block font-medium mb-2 text-gray-300 text-sm">Protocol</label>
                <select onchange="applyFilters()" id="protocol-select" class="w-full px-3 py-2 rounded-lg input-dark text-base focus:ring-2">
                    ${protocolOptions}
                </select>
            </div>
        `);

        // Country Dropdown
        const countries = new Set(cachedPrxList.map(p => p.country));
        let countryOptions = '<option value="all" ' + ('all' === selectedCountry.toLowerCase() ? 'selected' : '') + '>All Countries</option>';
        for (const country of [...countries].sort()) {
            countryOptions += `<option value="${country}" ${selectedCountry === country ? 'selected' : ''}>${getFlagEmoji(country)} ${country}</option>`;
        }
        this.html = this.html.replace('PLACEHOLDER_COUNTRY_DROPDOWN', `
            <div class="relative">
                <label for="country-select" class="block font-medium mb-2 text-gray-300 text-sm">Country</label>
                <select onchange="applyFilters()" id="country-select" class="w-full px-3 py-2 rounded-lg input-dark text-base focus:ring-2">
                    ${countryOptions}
                </select>
            </div>
        `);

        // Host Dropdown
        const hosts = [APP_DOMAIN, 'ava.game.naver.com', 'investor.fb.com'];
        let hostOptions = '';
        for (const host of hosts) {
            hostOptions += `<option value="${host}" ${selectedHost === host ? 'selected' : ''}>${host}</option>`;
        }
        this.html = this.html.replace('PLACEHOLDER_HOST_DROPDOWN', `
            <div class="relative">
                <label for="host-select" class="block font-medium mb-2 text-gray-300 text-sm">Wildcard/Host</label>
                <select onchange="applyFilters()" id="host-select" class="w-full px-3 py-2 rounded-lg input-dark text-base focus:ring-2">
                    ${hostOptions}
                </select>
            </div>
        `);

        // Port Dropdown
        const ports = [{
            value: 'all',
            label: 'All Ports'
        }, {
            value: '443',
            label: 'TLS (443)'
        }, {
            value: '80',
            label: 'NTLS (80)'
        }];
        let portOptions = '';
        for (const port of ports) {
            portOptions += `<option value="${port.value}" ${selectedPort === port.value ? 'selected' : ''}>${port.label}</option>`;
        }
        this.html = this.html.replace('PLACEHOLDER_PORT_DROPDOWN', `
            <div class="relative">
                <label for="port-select" class="block font-medium mb-2 text-gray-300 text-sm">Security/Port</label>
                <select onchange="applyFilters()" id="port-select" class="w-full px-3 py-2 rounded-lg input-dark text-base focus:ring-2">
                    ${portOptions}
                </select>
            </div>
        `);
    }
}
