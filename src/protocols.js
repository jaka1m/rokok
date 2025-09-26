import { PROTOCOLS } from './config.js';
import { arrayBufferToHex } from './utils.js';

/**
 * Sniffs the protocol from the initial data chunk.
 * @param {ArrayBuffer} buffer The initial data buffer.
 * @returns {Promise<string>} The detected protocol name.
 */
export async function protocolSniffer(buffer) {
    if (buffer.byteLength >= 62) {
        const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
        if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) {
            if (horseDelimiter[2] === 0x01 || horseDelimiter[2] === 0x03 || horseDelimiter[2] === 0x7f) {
                if (horseDelimiter[3] === 0x01 || horseDelimiter[3] === 0x03 || horseDelimiter[3] === 0x04) {
                    return PROTOCOLS[0]; // trojan
                }
            }
        }
    }

    // UUID v4 check for VLESS
    const flashDelimiter = new Uint8Array(buffer.slice(1, 17));
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(arrayBufferToHex(flashDelimiter))) {
        return PROTOCOLS[1]; // vless
    }

    return PROTOCOLS[2]; // default to ss
}

/**
 * Parses the Shadowsocks (SS) protocol header.
 * @param {ArrayBuffer} ssBuffer The buffer containing the SS data.
 * @returns {object} Parsed header information.
 */
export function readSsHeader(ssBuffer) {
    const view = new DataView(ssBuffer);
    const addressType = view.getUint8(0);
    let addressLength = 0;
    let addressValueIndex = 1;
    let addressValue = "";

    switch (addressType) {
        case 1: // IPv4
            addressLength = 4;
            addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 3: // Domain
            addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 4: // IPv6
            addressLength = 16;
            const ipv6 = [];
            const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `Invalid addressType for SS: ${addressType}` };
    }

    if (!addressValue) {
        return { hasError: true, message: `Destination address empty for SS, address type: ${addressType}` };
    }

    const portIndex = addressValueIndex + addressLength;
    const portRemote = new DataView(ssBuffer.slice(portIndex, portIndex + 2)).getUint16(0);

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType: addressType,
        portRemote: portRemote,
        rawClientData: ssBuffer.slice(portIndex + 2),
        isUDP: portRemote === 53,
    };
}

/**
 * Parses the VLESS protocol header.
 * @param {ArrayBuffer} buffer The buffer containing the VLESS data.
 * @returns {object} Parsed header information.
 */
export function readFlashHeader(buffer) {
    const version = new Uint8Array(buffer.slice(0, 1));
    const optLength = new Uint8Array(buffer.slice(17, 18))[0];
    const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];

    let isUDP = false;
    if (cmd === 1) { /* TCP */ } else if (cmd === 2) {
        isUDP = true;
    } else {
        return { hasError: true, message: `Unsupported VLESS command: ${cmd}` };
    }

    const portIndex = 18 + optLength + 1;
    const portRemote = new DataView(buffer.slice(portIndex, portIndex + 2)).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressType = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
    addressIndex += 1;

    let addressLength = 0;
    let addressValue = "";
    switch (addressType) {
        case 1: // IPv4
            addressLength = 4;
            addressValue = new Uint8Array(buffer.slice(addressIndex, addressIndex + addressLength)).join(".");
            break;
        case 2: // Domain
            addressLength = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            addressValue = new TextDecoder().decode(buffer.slice(addressIndex, addressIndex + addressLength));
            break;
        case 3: // IPv6
            addressLength = 16;
            const ipv6 = [];
            const dataView = new DataView(buffer.slice(addressIndex, addressIndex + addressLength));
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = `[${ipv6.join(":")}]`;
            break;
        default:
            return { hasError: true, message: `Invalid VLESS addressType: ${addressType}` };
    }

    if (!addressValue) {
        return { hasError: true, message: `Empty VLESS address, type: ${addressType}` };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType: addressType,
        portRemote: portRemote,
        rawClientData: buffer.slice(addressIndex + addressLength),
        version: new Uint8Array([version[0], 0]),
        isUDP: isUDP,
    };
}

/**
 * Parses the Trojan protocol header.
 * @param {ArrayBuffer} buffer The buffer containing the Trojan data.
 * @returns {object} Parsed header information.
 */
export function readHorseHeader(buffer) {
    const dataBuffer = buffer.slice(58);
    if (dataBuffer.byteLength < 6) {
        return { hasError: true, message: "Invalid Trojan request data" };
    }

    const view = new DataView(dataBuffer);
    const cmd = view.getUint8(0);
    let isUDP = false;
    if (cmd === 3) {
        isUDP = true;
    } else if (cmd !== 1) {
        return { hasError: true, message: `Unsupported Trojan command: ${cmd}` };
    }

    const addressType = view.getUint8(1);
    let addressValueIndex = 2;
    let addressLength = 0;
    let addressValue = "";

    switch (addressType) {
        case 1: // IPv4
            addressLength = 4;
            addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 3: // Domain
            addressLength = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 4: // IPv6
            addressLength = 16;
            const ipv6 = [];
            const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = `[${ipv6.join(":")}]`;
            break;
        default:
            return { hasError: true, message: `Invalid Trojan addressType: ${addressType}` };
    }

    if (!addressValue) {
        return { hasError: true, message: `Empty Trojan address, type: ${addressType}` };
    }

    const portIndex = addressValueIndex + addressLength;
    const portRemote = new DataView(dataBuffer.slice(portIndex, portIndex + 2)).getUint16(0);

    return {
        hasError: false,
        addressRemote: addressValue,
        portRemote: portRemote,
        rawClientData: dataBuffer.slice(portIndex + 4), // 2 bytes for port, 2 for CRLF
        isUDP: isUDP,
    };
}