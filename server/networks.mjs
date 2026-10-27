import { createHash, createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import { isIP } from "node:net";
import { join } from "node:path";

const keyPattern = /^[A-Za-z0-9+/]{43}=$/;
const safeIdPattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const maxConfigBytes = 256 * 1024;

function decodeKey(value, label) {
  if (typeof value !== "string" || !keyPattern.test(value)) {
    throw new Error(`${label} must be a base64-encoded 32-byte WireGuard key`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.length !== 32 || bytes.toString("base64") !== value) {
    throw new Error(`${label} must be a base64-encoded 32-byte WireGuard key`);
  }
  return bytes;
}

export function derivePublicKey(privateKey) {
  const privateBytes = decodeKey(privateKey, "PrivateKey");
  const pkcs8Prefix = Buffer.from("302e020100300506032b656e04220420", "hex");
  const privateObject = createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, privateBytes]),
    format: "der",
    type: "pkcs8",
  });
  const publicJwk = createPublicKey(privateObject).export({ format: "jwk" });
  return Buffer.from(publicJwk.x, "base64url").toString("base64");
}

function parseIp(ip) {
  const family = isIP(ip);
  if (family === 0) {
    throw new Error(`Invalid IP address: ${ip}`);
  }
  if (family === 4) {
    const value = ip.split(".").reduce((result, part) => (result << 8n) | BigInt(part), 0n);
    return { family, bits: 32, value };
  }

  let expandedIp = ip.toLowerCase();
  if (expandedIp.includes(".")) {
    const lastColon = expandedIp.lastIndexOf(":");
    const ipv4 = parseIp(expandedIp.slice(lastColon + 1));
    const high = Number((ipv4.value >> 16n) & 0xffffn).toString(16);
    const low = Number(ipv4.value & 0xffffn).toString(16);
    expandedIp = `${expandedIp.slice(0, lastColon)}:${high}:${low}`;
  }
  const halves = expandedIp.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const groups = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right] : left;
  const value = groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group || "0"}`), 0n);
  return { family, bits: 128, value };
}

function formatIp(value, family) {
  if (family === 4) {
    return [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 255n)).join(".");
  }
  const groups = Array.from({ length: 8 }, (_, index) => Number((value >> BigInt((7 - index) * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLength = 1;
  for (let index = 0; index < groups.length; ) {
    if (groups[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < groups.length && groups[end] === 0) {
      end += 1;
    }
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  if (bestStart === -1) {
    return groups.map((group) => group.toString(16)).join(":");
  }
  const left = groups
    .slice(0, bestStart)
    .map((group) => group.toString(16))
    .join(":");
  const right = groups
    .slice(bestStart + bestLength)
    .map((group) => group.toString(16))
    .join(":");
  return `${left}::${right}`;
}

function parseCidr(value, label = "CIDR") {
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string`);
  }
  const [ip, prefixText, ...rest] = value.trim().split("/");
  if (!ip || prefixText === undefined || rest.length > 0 || !/^\d+$/.test(prefixText)) {
    throw new Error(`${label} must include an IP address and prefix length`);
  }
  const parsed = parseIp(ip);
  const prefix = Number(prefixText);
  if (prefix < 0 || prefix > parsed.bits) {
    throw new Error(`${label} has an invalid prefix length`);
  }
  return { ...parsed, prefix, originalIp: ip };
}

function cidrNetwork(cidr) {
  const hostBits = BigInt(cidr.bits - cidr.prefix);
  const mask = hostBits === BigInt(cidr.bits) ? 0n : ((1n << BigInt(cidr.bits)) - 1n) ^ ((1n << hostBits) - 1n);
  return cidr.value & mask;
}

function cidrsOverlap(left, right) {
  if (left.family !== right.family) {
    return false;
  }
  const prefix = Math.min(left.prefix, right.prefix);
  const hostBits = BigInt(left.bits - prefix);
  const mask = prefix === 0 ? 0n : ((1n << BigInt(left.bits)) - 1n) ^ ((1n << hostBits) - 1n);
  return (left.value & mask) === (right.value & mask);
}

function addressInCidr(address, cidr) {
  return address.family === cidr.family && cidrsOverlap({ ...address, prefix: address.bits }, cidr);
}

function networkCidrs(addressText) {
  return addressText
    .split(",")
    .map((address) => {
      const cidr = parseCidr(address.trim(), "Server Address");
      return `${formatIp(cidrNetwork(cidr), cidr.family)}/${cidr.prefix}`;
    })
    .join(", ");
}

function parseAllowedIps(value, label) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${label} is required`);
  }
  return value.split(",").map((part) => parseCidr(part.trim(), label));
}

function validateEndpoint(value) {
  if (typeof value !== "string" || value.length > 253 || /\s/.test(value)) {
    throw new Error("Server Endpoint must be a host and port, such as vpn.example.com:51820");
  }
  let host;
  let portText;
  const ipv6 = value.match(/^\[([0-9a-fA-F:]+)]:(\d+)$/);
  if (ipv6) {
    [, host, portText] = ipv6;
    if (isIP(host) !== 6) {
      throw new Error("Server Endpoint has an invalid IPv6 address");
    }
  } else {
    const match = value.match(/^([^:]+):(\d+)$/);
    if (!match) {
      throw new Error("Server Endpoint must include a port");
    }
    [, host, portText] = match;
    if (
      isIP(host) !== 4 &&
      !/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.?$/.test(
        host,
      )
    ) {
      throw new Error("Server Endpoint has an invalid host");
    }
  }
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Server Endpoint has an invalid port");
  }
}

const interfaceDirectives = new Set([
  "Address",
  "DNS",
  "FwMark",
  "ListenPort",
  "MTU",
  "PostDown",
  "PostUp",
  "PreDown",
  "PreUp",
  "PrivateKey",
  "SaveConfig",
  "Table",
]);
const peerDirectives = new Set(["AllowedIPs", "Endpoint", "PersistentKeepalive", "PresharedKey", "PublicKey"]);

export function parseWgConfig(text, label = "WireGuard config") {
  if (typeof text !== "string" || Buffer.byteLength(text) > maxConfigBytes) {
    throw new Error(`${label} is missing or exceeds the 256 KB limit`);
  }
  const sections = [];
  let current;
  for (const [lineIndex, rawLine] of text.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const sectionMatch = line.match(/^\[(Interface|Peer)]$/i);
    if (sectionMatch) {
      const type = sectionMatch[1].toLowerCase();
      if (type === "interface" && sections.length > 0) {
        throw new Error(`${label} may contain only one [Interface] section`);
      }
      current = { type, values: new Map() };
      sections.push(current);
      continue;
    }
    if (!current) {
      throw new Error(`${label} has a setting outside a section on line ${lineIndex + 1}`);
    }
    const separator = line.indexOf("=");
    if (separator < 1) {
      throw new Error(`${label} has an invalid setting on line ${lineIndex + 1}`);
    }
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    const directives = current.type === "interface" ? interfaceDirectives : peerDirectives;
    if (!directives.has(key) || !value) {
      throw new Error(`${label} has an unsupported or empty ${key || "setting"} on line ${lineIndex + 1}`);
    }
    if (current.values.has(key) && ["Address", "DNS", "AllowedIPs"].includes(key)) {
      current.values.set(key, `${current.values.get(key)}, ${value}`);
      continue;
    }
    if (current.values.has(key) && ["PreDown", "PreUp", "PostDown", "PostUp"].includes(key)) {
      current.values.set(key, `${current.values.get(key)}\n${value}`);
      continue;
    }
    if (current.values.has(key)) {
      throw new Error(`${label} contains duplicate ${key} settings`);
    }
    current.values.set(key, value);
  }
  if (sections.length === 0 || sections[0].type !== "interface") {
    throw new Error(`${label} must start with one [Interface] section`);
  }
  return {
    interface: sections[0].values,
    peers: sections.slice(1).map((section) => section.values),
  };
}

function required(values, key, label) {
  const value = values.get(key);
  if (!value) {
    throw new Error(`${label} is missing ${key}`);
  }
  return value;
}

function validateAddresses(values, label) {
  const raw = required(values, "Address", label);
  return raw.split(",").map((entry) => parseCidr(entry.trim(), `${label} Address`));
}

function validateDns(value, label) {
  if (!value) {
    return "";
  }
  const servers = value.split(",").map((entry) => entry.trim());
  if (servers.some((server) => isIP(server) === 0)) {
    throw new Error(`${label} DNS must contain IP addresses`);
  }
  return servers.join(", ");
}

function validatePeerBlock(peer, label) {
  const publicKey = required(peer, "PublicKey", label);
  decodeKey(publicKey, `${label} PublicKey`);
  const allowed = parseAllowedIps(required(peer, "AllowedIPs", label), `${label} AllowedIPs`);
  const endpoint = peer.get("Endpoint");
  if (endpoint) {
    validateEndpoint(endpoint);
  }
  const keepalive = peer.get("PersistentKeepalive");
  if (keepalive !== undefined && (!/^\d+$/.test(keepalive) || Number(keepalive) > 65535)) {
    throw new Error(`${label} PersistentKeepalive must be between 0 and 65535`);
  }
  if (peer.has("PresharedKey")) {
    decodeKey(peer.get("PresharedKey"), `${label} PresharedKey`);
  }
  return { publicKey, allowed };
}

function inspectServerConfig(serverConfig) {
  const parsed = parseWgConfig(serverConfig, "Server config");
  const privateKey = required(parsed.interface, "PrivateKey", "Server config");
  const publicKey = derivePublicKey(privateKey);
  const addresses = validateAddresses(parsed.interface, "Server config");
  validateDns(parsed.interface.get("DNS"), "Server config");
  const listenPort = Number(required(parsed.interface, "ListenPort", "Server config"));
  if (!/^\d+$/.test(parsed.interface.get("ListenPort")) || listenPort < 1 || listenPort > 65535) {
    throw new Error("Server config ListenPort must be between 1 and 65535");
  }
  const peers = parsed.peers.map((peer, index) => validatePeerBlock(peer, `Server peer ${index + 1}`));
  if (
    peers.some((peer) => peer.allowed.some((allowed) => addresses.some((address) => addressInCidr(address, allowed))))
  ) {
    throw new Error("Server peer AllowedIPs cannot include a server interface address");
  }
  const publicKeys = new Set();
  for (const peer of peers) {
    if (peer.publicKey === publicKey || publicKeys.has(peer.publicKey)) {
      throw new Error("Server config contains a duplicate or invalid peer public key");
    }
    publicKeys.add(peer.publicKey);
  }
  ensureUniqueCidrs(
    peers.flatMap((peer) => peer.allowed),
    "Server peer AllowedIPs",
  );
  return { parsed, privateKey, publicKey, addresses, listenPort, peers };
}

function inspectClientConfig(config, label) {
  const parsed = parseWgConfig(config, label);
  if (parsed.peers.length !== 1) {
    throw new Error(`${label} must contain exactly one [Peer] section`);
  }
  const privateKey = required(parsed.interface, "PrivateKey", label);
  const publicKey = derivePublicKey(privateKey);
  const addresses = validateAddresses(parsed.interface, label);
  validateDns(parsed.interface.get("DNS"), label);
  const peer = validatePeerBlock(parsed.peers[0], `${label} peer`);
  const allowedIps = parseAllowedIps(required(parsed.peers[0], "AllowedIPs", label), `${label} AllowedIPs`);
  return { parsed, privateKey, publicKey, addresses, serverPeer: peer, allowedIps };
}

function ensurePeerAddressMatch(client, serverPeer, serverAddresses, label) {
  if (client.addresses.some((address) => address.prefix !== address.bits)) {
    throw new Error(`${label} addresses must use /32 or /128 host prefixes`);
  }
  ensureUniqueCidrs(client.addresses, `${label} addresses`);
  const clientIps = client.addresses.map((address) => ({ ...address, prefix: address.bits }));
  if (
    !clientIps.every((ip) => serverPeer.allowed.some((allowed) => addressInCidr(ip, allowed))) ||
    !clientIps.every((ip) => serverAddresses.some((address) => addressInCidr(ip, address))) ||
    clientIps.some((ip) => serverAddresses.some((address) => ip.value === address.value))
  ) {
    throw new Error(`${label} address does not match the server peer AllowedIPs`);
  }
}

export function validatePairedConfigs({ name, serverConfig, peers }) {
  validateNetworkName(name);
  if (!Array.isArray(peers) || peers.length > 256) {
    throw new Error("Peers must be an array with no more than 256 configs");
  }
  const server = inspectServerConfig(serverConfig);
  if (server.peers.length !== peers.length) {
    throw new Error("Each server peer must have exactly one matching client config");
  }
  const usedServerPeers = new Set();
  const usedClientKeys = new Set();
  const importedEndpoint = { value: undefined };
  const importedDns = { value: undefined };
  const normalizedPeers = peers.map((peer, index) => {
    if (!peer || typeof peer !== "object" || typeof peer.config !== "string") {
      throw new Error(`Client config ${index + 1} is invalid`);
    }
    const label = `Client config ${index + 1}`;
    const client = inspectClientConfig(peer.config, label);
    if (client.serverPeer.publicKey !== server.publicKey) {
      throw new Error(`${label} does not point to this server's public key`);
    }
    if (usedClientKeys.has(client.publicKey)) {
      throw new Error("Multiple client configs use the same key pair");
    }
    usedClientKeys.add(client.publicKey);
    const matchIndex = server.peers.findIndex((serverPeer, peerIndex) => {
      return !usedServerPeers.has(peerIndex) && serverPeer.publicKey === client.publicKey;
    });
    if (matchIndex === -1) {
      throw new Error(`${label} public key has no matching server peer`);
    }
    const serverPeer = server.peers[matchIndex];
    if (client.serverPeer.publicKey !== server.publicKey) {
      throw new Error(`${label} has an unexpected server public key`);
    }
    const serverPresharedKey = server.parsed.peers[matchIndex].get("PresharedKey");
    const clientPresharedKey = client.parsed.peers[0].get("PresharedKey");
    if (serverPresharedKey !== clientPresharedKey) {
      throw new Error(`${label} preshared key does not match the server config`);
    }
    ensurePeerAddressMatch(client, serverPeer, server.addresses, label);
    const endpoint = client.parsed.peers[0].get("Endpoint") ?? "";
    const dns = client.parsed.interface.get("DNS") ?? "";
    if (importedEndpoint.value !== undefined && importedEndpoint.value !== endpoint) {
      throw new Error("All imported client configs must use the same server endpoint");
    }
    if (importedDns.value !== undefined && importedDns.value !== dns) {
      throw new Error("All imported client configs must use the same DNS servers");
    }
    importedEndpoint.value = endpoint;
    importedDns.value = dns;
    usedServerPeers.add(matchIndex);
    const allowedIPs = client.parsed.peers[0].get("AllowedIPs");
    const canonicalAllowedIPs = allowedIPs
      .split(",")
      .map((route) => route.trim())
      .join(", ");
    const vpnRoute = networkCidrs(required(server.parsed.interface, "Address", "Server config"));
    const routeMode =
      canonicalAllowedIPs === "0.0.0.0/0, ::/0" ? "full" : canonicalAllowedIPs === vpnRoute ? "vpn" : "custom";
    const peerName = validateNetworkName(
      typeof peer.name === "string" && peer.name.trim() ? peer.name.trim() : `Peer ${index + 1}`,
    );
    return {
      name: peerName,
      address: required(client.parsed.interface, "Address", label),
      serverAllowedIPs: server.parsed.peers[matchIndex].get("AllowedIPs"),
      presharedKey: clientPresharedKey ?? "",
      privateKey: client.privateKey,
      publicKey: client.publicKey,
      routeMode,
      customAllowedIPs: routeMode === "custom" ? allowedIPs : "",
      allowedIPs,
      persistentKeepalive: Number(client.parsed.peers[0].get("PersistentKeepalive") ?? 0),
      enabled: true,
      config: peer.config,
    };
  });
  return {
    name: name.trim(),
    server: {
      interfaceName: "wg0",
      address: required(server.parsed.interface, "Address", "Server config"),
      listenPort: server.listenPort,
      endpoint: importedEndpoint.value ?? "",
      dns: importedDns.value ?? "",
      privateKey: server.privateKey,
      publicKey: server.publicKey,
    },
    serverConfig,
    peers: normalizedPeers,
  };
}

export function validateNetworkName(name) {
  if (
    typeof name !== "string" ||
    !name.trim() ||
    name.trim().length > 80 ||
    [...name].some((character) => character.codePointAt(0) <= 31 || character.codePointAt(0) === 127)
  ) {
    throw new Error("Network name must be between 1 and 80 printable characters");
  }
  return name.trim();
}

function networkId(name) {
  const id = name
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
  if (id && safeIdPattern.test(id)) {
    return id;
  }
  const suffix = createHash("sha256").update(name.normalize("NFKC").toLowerCase()).digest("hex").slice(0, 12);
  return `network-${suffix}`;
}

function ensureUniqueCidrs(cidrs, label) {
  for (let left = 0; left < cidrs.length; left += 1) {
    for (let right = left + 1; right < cidrs.length; right += 1) {
      if (cidrsOverlap(cidrs[left], cidrs[right])) {
        throw new Error(`${label} contains overlapping routes`);
      }
    }
  }
}

function normalizeModel(input) {
  if (!input || typeof input !== "object") {
    throw new Error("Network data must be an object");
  }
  const name = validateNetworkName(input.name);
  const serverInput = input.server;
  if (!serverInput || typeof serverInput !== "object") {
    throw new Error("Server settings are required");
  }
  const interfaceName = typeof serverInput.interfaceName === "string" ? serverInput.interfaceName.trim() : "";
  if (!/^[a-zA-Z0-9_.+=-]{1,15}$/.test(interfaceName)) {
    throw new Error("Interface name must be 1-15 letters, numbers, dots, underscores, pluses, or hyphens");
  }
  const address = typeof serverInput.address === "string" ? serverInput.address.trim() : "";
  const serverAddresses = address.split(",").map((entry) => parseCidr(entry.trim(), "Server Address"));
  ensureUniqueCidrs(serverAddresses, "Server Address");
  const listenPort = Number(serverInput.listenPort);
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
    throw new Error("Listen port must be between 1 and 65535");
  }
  const privateKey = serverInput.privateKey;
  const publicKey = derivePublicKey(privateKey);
  if (serverInput.publicKey && serverInput.publicKey !== publicKey) {
    throw new Error("Server public key does not match its private key");
  }
  const endpoint = typeof serverInput.endpoint === "string" ? serverInput.endpoint.trim() : "";
  validateEndpoint(endpoint);
  const dns = validateDns(typeof serverInput.dns === "string" ? serverInput.dns.trim() : "", "Network");
  if (!Array.isArray(input.peers) || input.peers.length > 256) {
    throw new Error("Peers must be an array with no more than 256 entries");
  }
  const peers = input.peers.map((peer, index) => {
    if (!peer || typeof peer !== "object") {
      throw new Error(`Peer ${index + 1} is invalid`);
    }
    const peerName = validateNetworkName(peer.name);
    const clientAddressText = typeof peer.address === "string" ? peer.address.trim() : "";
    const clientAddresses = clientAddressText.split(",").map((entry) => parseCidr(entry.trim(), `${peerName} address`));
    if (clientAddresses.some((clientAddress) => clientAddress.prefix !== clientAddress.bits)) {
      throw new Error(`${peerName} address must use /32 or /128 host prefixes`);
    }
    for (const clientAddress of clientAddresses) {
      if (!serverAddresses.some((serverAddress) => addressInCidr(clientAddress, serverAddress))) {
        throw new Error(`${peerName} address must be inside the server VPN subnet`);
      }
      if (serverAddresses.some((serverAddress) => serverAddress.value === clientAddress.value)) {
        throw new Error(`${peerName} address cannot use a server interface address`);
      }
    }
    ensureUniqueCidrs(clientAddresses, `${peerName} address`);
    const clientPrivateKey = peer.privateKey;
    const clientPublicKey = derivePublicKey(clientPrivateKey);
    if (peer.publicKey && peer.publicKey !== clientPublicKey) {
      throw new Error(`${peerName} public key does not match its private key`);
    }
    const presharedKey = typeof peer.presharedKey === "string" ? peer.presharedKey.trim() : "";
    if (presharedKey) {
      decodeKey(presharedKey, `${peerName} PresharedKey`);
    }
    const routeMode = peer.routeMode;
    let allowedIPs;
    if (routeMode === "full") {
      allowedIPs = "0.0.0.0/0, ::/0";
    } else if (routeMode === "vpn") {
      allowedIPs = networkCidrs(address);
    } else if (routeMode === "custom") {
      allowedIPs = typeof peer.customAllowedIPs === "string" ? peer.customAllowedIPs.trim() : "";
      const routes = parseAllowedIps(allowedIPs, `${peerName} custom AllowedIPs`);
      ensureUniqueCidrs(routes, `${peerName} custom AllowedIPs`);
    } else {
      throw new Error(`${peerName} has an unsupported routing mode`);
    }
    const keepalive = Number(peer.persistentKeepalive ?? 25);
    if (!Number.isInteger(keepalive) || keepalive < 0 || keepalive > 65535) {
      throw new Error(`${peerName} PersistentKeepalive must be between 0 and 65535`);
    }
    const serverAllowedIPs =
      typeof peer.serverAllowedIPs === "string" && peer.serverAllowedIPs.trim()
        ? peer.serverAllowedIPs.trim()
        : clientAddressText;
    const serverAllowedCidrs = parseAllowedIps(serverAllowedIPs, `${peerName} server AllowedIPs`);
    if (
      !clientAddresses.every((clientAddress) =>
        serverAllowedCidrs.some((allowed) => addressInCidr(clientAddress, allowed)),
      )
    ) {
      throw new Error(`${peerName} server AllowedIPs must include every client VPN address`);
    }
    if (
      serverAllowedCidrs.some((allowed) =>
        serverAddresses.some((serverAddress) => addressInCidr(serverAddress, allowed)),
      )
    ) {
      throw new Error(`${peerName} server AllowedIPs cannot include a server interface address`);
    }
    return {
      name: peerName,
      address: clientAddressText,
      serverAllowedIPs,
      privateKey: clientPrivateKey,
      publicKey: clientPublicKey,
      presharedKey,
      routeMode,
      customAllowedIPs: routeMode === "custom" ? allowedIPs : "",
      allowedIPs,
      persistentKeepalive: keepalive,
      enabled: peer.enabled !== false,
    };
  });
  const peerAddresses = peers.flatMap((peer) => parseAllowedIps(peer.address, `${peer.name} address`));
  for (let left = 0; left < peerAddresses.length; left += 1) {
    for (let right = left + 1; right < peerAddresses.length; right += 1) {
      if (cidrsOverlap(peerAddresses[left], peerAddresses[right])) {
        throw new Error("Peer VPN addresses must be unique and non-overlapping");
      }
    }
  }
  if (new Set(peers.map((peer) => peer.publicKey)).size !== peers.length) {
    throw new Error("Each peer must have a unique public key");
  }
  ensureUniqueCidrs(
    peers.flatMap((peer) => parseAllowedIps(peer.serverAllowedIPs, `${peer.name} server AllowedIPs`)),
    "Server peer AllowedIPs",
  );
  return {
    name,
    server: { interfaceName, address, listenPort, endpoint, dns, privateKey, publicKey },
    peers,
  };
}

export function generateNetworkConfigs(input) {
  const network = normalizeModel(input);
  const activePeers = network.peers.filter((peer) => peer.enabled);
  let serverConfig = `[Interface]\nAddress = ${network.server.address}\nPrivateKey = ${network.server.privateKey}\nListenPort = ${network.server.listenPort}\n`;
  for (const peer of activePeers) {
    serverConfig += `\n[Peer]\nPublicKey = ${peer.publicKey}${peer.presharedKey ? `\nPresharedKey = ${peer.presharedKey}` : ""}\nAllowedIPs = ${peer.serverAllowedIPs}\n`;
  }
  const peers = network.peers.map((peer) => {
    const clientConfig = `[Interface]\nAddress = ${peer.address}\nPrivateKey = ${peer.privateKey}${network.server.dns ? `\nDNS = ${network.server.dns}` : ""}\n\n[Peer]\nPublicKey = ${network.server.publicKey}${peer.presharedKey ? `\nPresharedKey = ${peer.presharedKey}` : ""}\nEndpoint = ${network.server.endpoint}\nAllowedIPs = ${peer.allowedIPs}\nPersistentKeepalive = ${peer.persistentKeepalive}\n`;
    return { ...peer, config: clientConfig };
  });
  validatePairedConfigs({
    name: network.name,
    serverConfig,
    peers: activePeers.map((peer) => peers.find((item) => item.name === peer.name)),
  });
  return { ...network, serverConfig, peers };
}

export function generateKeyPair() {
  const privateBytes = randomBytes(32);
  const privateKey = privateBytes.toString("base64");
  return { privateKey, publicKey: derivePublicKey(privateKey) };
}

export function createNetworkStore(directory) {
  let directoryReady;

  async function ensureDirectory() {
    if (!directoryReady) {
      directoryReady = (async () => {
        await mkdir(directory, { recursive: true, mode: 0o700 });
        const metadata = await lstat(directory);
        if (!metadata.isDirectory()) {
          throw new Error("Network storage path must be a directory");
        }
        await chmod(directory, 0o700);
        const entries = await readdir(directory, { withFileTypes: true });
        for (const entry of entries) {
          if (!entry.isDirectory()) {
            continue;
          }
          const temporary = entry.name.match(/^\.([a-z0-9]+(?:-[a-z0-9]+)*)\.[a-f0-9]{16}\.tmp$/);
          if (temporary) {
            await rm(join(directory, entry.name), { recursive: true, force: true });
            continue;
          }
          const backup = entry.name.match(/^\.([a-z0-9]+(?:-[a-z0-9]+)*)\.[a-f0-9]{16}\.backup$/);
          if (!backup) {
            continue;
          }
          const target = join(directory, backup[1]);
          try {
            await lstat(target);
            await rm(join(directory, entry.name), { recursive: true, force: true });
          } catch (error) {
            if (error?.code !== "ENOENT") {
              throw error;
            }
            await rename(join(directory, entry.name), target);
          }
        }
      })();
    }
    return directoryReady;
  }

  function filePath(id) {
    if (typeof id !== "string" || !safeIdPattern.test(id)) {
      throw new Error("Invalid network id");
    }
    return join(directory, id);
  }

  async function readNetwork(id) {
    const path = filePath(id);
    const metadata = await lstat(path);
    if (!metadata.isDirectory()) {
      throw new Error("Stored network directory is invalid");
    }
    const manifestPath = join(path, "network.json");
    const manifestMetadata = await lstat(manifestPath);
    if (!manifestMetadata.isFile() || manifestMetadata.size > 1024 * 1024) {
      throw new Error("Stored network manifest is invalid or too large");
    }
    const network = JSON.parse(await readFile(manifestPath, "utf8"));
    if (network.id !== id) {
      throw new Error("Stored network identifier does not match its filename");
    }
    if (typeof network.serverConfig !== "string" || Buffer.byteLength(network.serverConfig) > maxConfigBytes) {
      throw new Error("Stored server config is invalid or too large");
    }
    const serverConfigPath = join(path, "server.conf");
    const serverConfigMetadata = await lstat(serverConfigPath);
    if (!serverConfigMetadata.isFile() || serverConfigMetadata.size > maxConfigBytes) {
      throw new Error("Stored server config file is invalid or too large");
    }
    const serverConfig = await readFile(serverConfigPath, "utf8");
    if (serverConfig !== network.serverConfig || !Array.isArray(network.peers)) {
      throw new Error("Stored server config does not match its manifest");
    }
    const peersDirectory = join(path, "peers");
    if (!(await lstat(peersDirectory)).isDirectory()) {
      throw new Error("Stored peer config directory is invalid");
    }
    for (const [index, peer] of network.peers.entries()) {
      const configPath = `peers/${String(index + 1).padStart(3, "0")}.conf`;
      if (typeof peer.config !== "string" || Buffer.byteLength(peer.config) > maxConfigBytes) {
        throw new Error("Stored client config is invalid or too large");
      }
      const clientConfigPath = join(path, configPath);
      const clientConfigMetadata = await lstat(clientConfigPath);
      if (!clientConfigMetadata.isFile() || clientConfigMetadata.size > maxConfigBytes) {
        throw new Error("Stored client config file is invalid or too large");
      }
      if ((await readFile(clientConfigPath, "utf8")) !== peer.config) {
        throw new Error("Stored client config does not match its manifest");
      }
    }
    return network;
  }

  async function hasDuplicateName(name, exceptId) {
    const nameKey = name.normalize("NFKC").trim().toLowerCase();
    const files = await readdir(directory, { withFileTypes: true });
    for (const file of files) {
      if (!file.isDirectory() || !safeIdPattern.test(file.name) || file.name === exceptId) {
        continue;
      }
      try {
        const network = await readNetwork(file.name);
        if (network.name.normalize("NFKC").trim().toLowerCase() === nameKey) {
          return true;
        }
      } catch {
        // Ignore corrupt or unrelated directories during duplicate-name checks.
      }
    }
    return false;
  }

  async function writePrivateFile(path, content) {
    const handle = await open(path, "wx", 0o600);
    try {
      await handle.writeFile(content, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  return {
    async list() {
      await ensureDirectory();
      const files = await readdir(directory, { withFileTypes: true });
      const networks = [];
      for (const file of files) {
        if (!file.isDirectory() || !safeIdPattern.test(file.name)) {
          continue;
        }
        try {
          const network = await readNetwork(file.name);
          networks.push({
            id: network.id,
            name: network.name,
            createdAt: network.createdAt,
            updatedAt: network.updatedAt,
          });
        } catch {
          // Ignore unrelated or corrupt files rather than making all network access unavailable.
        }
      }
      return networks.sort((left, right) => left.name.localeCompare(right.name));
    },

    async get(id) {
      await ensureDirectory();
      return readNetwork(id);
    },

    async save(network, id) {
      await ensureDirectory();
      const targetId = id ?? networkId(network.name);
      const path = filePath(targetId);
      let existing;
      try {
        existing = await readNetwork(targetId);
        if (existing && !id) {
          throw Object.assign(new Error("A network with this name already exists"), { statusCode: 409 });
        }
      } catch (error) {
        if (error?.statusCode === 409) {
          throw error;
        }
        if (error?.code !== "ENOENT") {
          throw error;
        }
        if (id) {
          throw Object.assign(new Error("Network not found"), { code: "ENOENT" });
        }
      }
      if (await hasDuplicateName(network.name, targetId)) {
        throw Object.assign(new Error("A network with this name already exists"), { statusCode: 409 });
      }
      const now = new Date().toISOString();
      let record = {
        ...network,
        id: targetId,
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      };
      record = {
        ...record,
        peers: record.peers.map((peer, index) => ({
          ...peer,
          configFile: `peers/${String(index + 1).padStart(3, "0")}.conf`,
        })),
      };
      const temporaryPath = join(directory, `.${targetId}.${randomBytes(8).toString("hex")}.tmp`);
      const backupPath = join(directory, `.${targetId}.${randomBytes(8).toString("hex")}.backup`);
      let movedExisting = false;
      try {
        await mkdir(temporaryPath, { mode: 0o700 });
        await mkdir(join(temporaryPath, "peers"), { mode: 0o700 });
        await writePrivateFile(join(temporaryPath, "server.conf"), record.serverConfig);
        for (const peer of record.peers) {
          await writePrivateFile(join(temporaryPath, peer.configFile), peer.config);
        }
        await writePrivateFile(join(temporaryPath, "network.json"), `${JSON.stringify(record, null, 2)}\n`);
        if (existing) {
          await rename(path, backupPath);
          movedExisting = true;
        }
        try {
          await rename(temporaryPath, path);
        } catch (error) {
          if (movedExisting) {
            await rename(backupPath, path);
            movedExisting = false;
          }
          throw error;
        }
        if (movedExisting) {
          movedExisting = false;
          await rm(backupPath, { recursive: true, force: true }).catch(() => {});
        }
      } catch (error) {
        await rm(temporaryPath, { recursive: true, force: true }).catch(() => {});
        if (movedExisting) {
          await rename(backupPath, path).catch(() => {});
        }
        throw error;
      }
      return record;
    },

    async remove(id) {
      await ensureDirectory();
      const path = filePath(id);
      if (!(await lstat(path)).isDirectory()) {
        throw new Error("Stored network directory is invalid");
      }
      await rm(path, { recursive: true });
    },
  };
}
