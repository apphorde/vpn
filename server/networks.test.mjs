import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rename, stat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import {
  createNetworkStore,
  derivePublicKey,
  generateKeyPair,
  generateNetworkConfigs,
  parseWgConfig,
  validatePairedConfigs,
} from "./networks.mjs";

let dataDirectory;

after(async () => {
  if (dataDirectory) {
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

function networkInput(routeMode = "vpn") {
  const serverKeys = generateKeyPair();
  const clientKeys = generateKeyPair();
  return {
    name: "Office VPN",
    server: {
      interfaceName: "wg-office",
      address: "10.22.0.1/24",
      listenPort: 51820,
      endpoint: "vpn.example.com:51820",
      dns: "1.1.1.1",
      ...serverKeys,
    },
    peers: [
      {
        name: "Alice laptop",
        address: "10.22.0.2/32",
        ...clientKeys,
        routeMode,
        customAllowedIPs: "192.168.10.0/24",
        persistentKeepalive: 25,
        enabled: true,
      },
    ],
  };
}

test("X25519 public keys are derived from raw WireGuard private keys", () => {
  const privateKey = Buffer.from("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "hex").toString(
    "base64",
  );
  const expectedPublicKey = Buffer.from(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    "hex",
  ).toString("base64");
  assert.equal(derivePublicKey(privateKey), expectedPublicKey);
  assert.throws(() => derivePublicKey("not a key"), /base64-encoded 32-byte/);
});

test("WireGuard parsing accepts repeated address and AllowedIPs directives", () => {
  const parsed = parseWgConfig(
    `[Interface]\nAddress = 10.0.0.1/24\nAddress = fd42::1/64\n[Peer]\nAllowedIPs = 10.0.0.2/32\nAllowedIPs = fd42::2/128`,
  );
  assert.equal(parsed.interface.get("Address"), "10.0.0.1/24, fd42::1/64");
  assert.equal(parsed.peers[0].get("AllowedIPs"), "10.0.0.2/32, fd42::2/128");
});

test("server and client configs are generated with peer routes and a matching key pair", () => {
  const input = networkInput();
  input.peers[0].presharedKey = generateKeyPair().privateKey;
  input.peers[0].serverAllowedIPs = "10.22.0.2/32, 192.168.10.0/24";
  const network = generateNetworkConfigs(input);
  assert.match(network.serverConfig, /\[Interface\]/);
  assert.match(network.serverConfig, /AllowedIPs = 10\.22\.0\.2\/32, 192\.168\.10\.0\/24/);
  assert.ok(network.serverConfig.includes(`PresharedKey = ${input.peers[0].presharedKey}`));
  assert.match(network.peers[0].config, /Address = 10\.22\.0\.2\/32/);
  assert.match(network.peers[0].config, /AllowedIPs = 10\.22\.0\.0\/24/);
  assert.ok(network.peers[0].config.includes(`PresharedKey = ${input.peers[0].presharedKey}`));
  assert.match(network.peers[0].config, /PublicKey = /);
  assert.doesNotMatch(network.serverConfig, /Endpoint =/);
  const imported = validatePairedConfigs({
    name: network.name,
    serverConfig: network.serverConfig,
    peers: [{ name: network.peers[0].name, config: network.peers[0].config }],
  });
  assert.equal(imported.peers[0].publicKey, network.peers[0].publicKey);
  assert.equal(imported.peers[0].presharedKey, input.peers[0].presharedKey);
  assert.equal(imported.peers[0].serverAllowedIPs, input.peers[0].serverAllowedIPs);
  assert.equal(imported.server.publicKey, network.server.publicKey);
});

test("AllowedIPs supports full tunnel, VPN subnet, and validated custom routes", () => {
  const full = generateNetworkConfigs(networkInput("full"));
  assert.match(full.peers[0].config, /AllowedIPs = 0\.0\.0\.0\/0, ::\/0/);
  const custom = generateNetworkConfigs(networkInput("custom"));
  assert.match(custom.peers[0].config, /AllowedIPs = 192\.168\.10\.0\/24/);
  const invalid = networkInput("custom");
  invalid.peers[0].customAllowedIPs = "not-a-route";
  assert.throws(() => generateNetworkConfigs(invalid), /prefix length/);
});

test("VPN-subnet routes are calculated for dual-stack networks", () => {
  const input = networkInput();
  input.server.address = "10.22.0.1/24, fd42:1234::1/64";
  input.peers[0].address = "10.22.0.2/32, fd42:1234::2/128";
  const network = generateNetworkConfigs(input);
  assert.match(network.peers[0].config, /AllowedIPs = 10\.22\.0\.0\/24, fd42:1234::\/64/);
  assert.match(network.serverConfig, /AllowedIPs = 10\.22\.0\.2\/32, fd42:1234::2\/128/);
});

test("config validation rejects mismatched peers and out-of-subnet addresses", () => {
  const network = generateNetworkConfigs(networkInput());
  const clientKeyMismatch = generateNetworkConfigs(networkInput());
  assert.throws(
    () =>
      validatePairedConfigs({
        name: network.name,
        serverConfig: network.serverConfig,
        peers: [{ name: "Wrong peer", config: clientKeyMismatch.peers[0].config }],
      }),
    /does not point to this server's public key/,
  );
  const outsideSubnet = networkInput();
  outsideSubnet.peers[0].address = "10.23.0.4/32";
  assert.throws(() => generateNetworkConfigs(outsideSubnet), /inside the server VPN subnet/);
  const routeToServer = networkInput();
  routeToServer.peers[0].serverAllowedIPs = "10.22.0.0/24";
  assert.throws(() => generateNetworkConfigs(routeToServer), /cannot include a server interface address/);
});

test("stored network configs use private files and support update, listing, and deletion", async () => {
  dataDirectory = await mkdtemp(join(tmpdir(), "vpn-network-store-"));
  const directory = join(dataDirectory, "networks");
  const store = createNetworkStore(directory);
  const network = generateNetworkConfigs(networkInput());
  const stored = await store.save(network);
  assert.equal(stored.id, "office-vpn");
  const unicodeNetwork = await store.save({ ...network, name: "東京ネットワーク" });
  assert.match(unicodeNetwork.id, /^network-[a-f0-9]{12}$/);
  assert.equal((await store.list()).length, 2);
  const serverFile = join(directory, "office-vpn", "server.conf");
  const file = await stat(serverFile);
  assert.equal(file.mode & 0o777, 0o600);
  assert.match(await readFile(serverFile, "utf8"), /\[Interface\]/);
  const parsed = JSON.parse(await readFile(join(directory, "office-vpn", "network.json"), "utf8"));
  assert.equal(parsed.peers[0].privateKey, network.peers[0].privateKey);
  assert.match(await readFile(join(directory, "office-vpn", parsed.peers[0].configFile), "utf8"), /\[Peer\]/);
  await new Promise((resolve) => setTimeout(resolve, 2));
  const updated = await store.save({ ...network, name: "Office VPN v2" }, "office-vpn");
  assert.equal(updated.createdAt, stored.createdAt);
  assert.notEqual(updated.updatedAt, stored.updatedAt);
  await assert.rejects(store.save(network), /already exists/);
  await assert.rejects(store.save({ ...network, name: "Office VPN v2" }), /already exists/);
  await rename(join(directory, "office-vpn"), join(directory, ".office-vpn.0123456789abcdef.backup"));
  await mkdir(join(directory, ".stale-network.0123456789abcdef.tmp"));
  const recoveredStore = createNetworkStore(directory);
  assert.equal((await recoveredStore.get("office-vpn")).name, "Office VPN v2");
  assert.equal(
    (await readdir(directory)).some((entry) => entry.endsWith(".backup") || entry.endsWith(".tmp")),
    false,
  );
  await store.remove("office-vpn");
  await store.remove(unicodeNetwork.id);
  assert.deepEqual(await store.list(), []);
});
