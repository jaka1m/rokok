import { connect } from "cloudflare:sockets";
import {
    DNS_SERVER_ADDRESS,
    DNS_SERVER_PORT,
    WS_READY_STATE_OPEN,
    WS_READY_STATE_CLOSING,
    PROTOCOLS
} from './config.js';
import {
    protocolSniffer,
    readHorseHeader,
    readFlashHeader,
    readSsHeader
} from './protocols.js';
import { base64ToArrayBuffer } from './utils.js';

/**
 * Handles the WebSocket connection and proxies traffic.
 * @param {Request} request The incoming request.
 * @param {string} prxIP The IP of the proxy to connect to.
 */
export async function websocketHandler(request, prxIP) {
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

                    if (protocol === PROTOCOLS[0]) { // trojan
                        protocolHeader = readHorseHeader(chunk);
                    } else if (protocol === PROTOCOLS[1]) { // vless
                        protocolHeader = readFlashHeader(chunk);
                    } else if (protocol === PROTOCOLS[2]) { // ss
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
                            throw new Error("UDP only supports DNS port 53");
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
                        log,
                        prxIP // Pass prxIP down
                    );
                },
                close() {
                    log(`readableWebSocketStream is closed`);
                },
                abort(reason) {
                    log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
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

async function handleTCPOutBound(
    remoteSocket,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    responseHeader,
    log,
    prxIP // Accept prxIP as an argument
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
        const [proxyAddress, proxyPort] = (prxIP || "").split(/[:=-]/);
        const tcpSocket = await connectAndWrite(
            proxyAddress || addressRemote,
            proxyPort || portRemote
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
        console.error(`Error while handling UDP outbound: ${e.message}`);
    }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) return;
                controller.enqueue(event.data);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) return;
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer has error", err);
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
            if (readableStreamCancel) return;
            log(`ReadableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        },
    });
    return stream;
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
                        controller.error("WebSocket is not open, maybe closed");
                    }
                    if (header) {
                        webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                        header = null;
                    } else {
                        webSocket.send(chunk);
                    }
                },
                close() {
                    log(`remoteConnection readable is closed with hasIncomingData: ${hasIncomingData}`);
                },
                abort(reason) {
                    console.error(`remoteConnection readable aborted:`, reason);
                },
            })
        )
        .catch((error) => {
            console.error(`remoteSocketToWS has exception:`, error.stack || error);
            safeCloseWebSocket(webSocket);
        });

    if (!hasIncomingData && retry) {
        log(`Retrying connection...`);
        retry();
    }
}

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error:", error);
    }
}