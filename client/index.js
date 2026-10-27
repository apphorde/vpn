class WireGuardManager {
  constructor() {
    this.peers = [];
    this.peerCounter = 0;
    this.serverKeys = { private: "", public: "" };
    this.networkId = "";
    this.savedNetwork = null;
    this.dirty = false;
    this.init();
  }

  init() {
    this.bindEvents();
    this.updatePeersDisplay();
    this.updateConfigOutput();
    this.refreshNetworks().catch((error) => this.showToast(error.message));
  }

  bindEvents() {
    document.getElementById("generateServerKeys").addEventListener("click", () => this.generateServerKeys());
    document.getElementById("copyServerPrivate").addEventListener("click", () => {
      this.copyToClipboard(this.serverKeys.private, "Server private key copied!");
    });
    document.getElementById("copyServerPublic").addEventListener("click", () => {
      this.copyToClipboard(this.serverKeys.public, "Server public key copied!");
    });
    document.getElementById("addPeer").addEventListener("click", () => this.addPeer());
    document.getElementById("exportConfig").addEventListener("click", () => this.exportConfiguration());
    document.getElementById("darkModeToggle").addEventListener("click", () => this.toggleDarkMode());
    document.getElementById("signOutButton").addEventListener("click", () => {
      document.getElementById("logoutForm").requestSubmit();
    });
    document.getElementById("newNetwork").addEventListener("click", () => this.newNetwork());
    document.getElementById("saveNetwork").addEventListener("click", () => this.saveNetwork());
    document.getElementById("deleteNetwork").addEventListener("click", () => this.deleteNetwork());
    document.getElementById("importNetwork").addEventListener("click", () => this.importNetwork());
    document.getElementById("savedNetworks").addEventListener("change", (event) => {
      if (event.target.value) {
        this.loadNetwork(event.target.value).catch((error) => this.showToast(error.message));
      } else {
        this.newNetwork();
      }
    });
    document.getElementById("peersContainer").addEventListener("click", (event) => this.handlePeerAction(event));
    document.getElementById("peersContainer").addEventListener("change", (event) => this.handlePeerChange(event));
    ["serverPort", "serverInterface", "serverIP", "serverEndpoint", "serverDNS"].forEach((id) => {
      document.getElementById(id).addEventListener("input", () => this.markDirty());
    });
    document.getElementById("networkName").addEventListener("input", () => this.markDirty());
  }

  async api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: {
        Accept: "application/json",
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...options.headers,
      },
    });
    if (response.status === 401) {
      window.location.assign("/");
      throw new Error("Please sign in to continue.");
    }
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(result.error || "The request failed.");
    }
    return result;
  }

  async requestKeyPair() {
    return this.api("/api/keys", { method: "POST", headers: { "Content-Type": "application/json" } });
  }

  async generateServerKeys() {
    try {
      this.serverKeys = await this.requestKeyPair();
      document.getElementById("serverPrivateKey").value = this.serverKeys.privateKey;
      document.getElementById("serverPublicKey").value = this.serverKeys.publicKey;
      this.serverKeys = { private: this.serverKeys.privateKey, public: this.serverKeys.publicKey };
      this.markDirty();
      this.showToast("Server keys generated successfully.");
    } catch (error) {
      this.showToast(error.message || "Key generation failed. Please sign in again.");
    }
  }

  addPeer() {
    const id = ++this.peerCounter;
    this.peers.push({
      id,
      name: `Peer ${id}`,
      address: this.nextPeerAddress(),
      serverAllowedIPs: "",
      privateKey: "",
      publicKey: "",
      presharedKey: "",
      routeMode: "vpn",
      customAllowedIPs: "",
      allowedIPs: "",
      persistentKeepalive: 25,
      enabled: true,
      config: "",
    });
    this.markDirty();
    this.updatePeersDisplay();
  }

  nextPeerAddress() {
    const serverAddress = document.getElementById("serverIP").value.trim().split(",")[0].trim();
    const match = serverAddress.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (!match) {
      return "";
    }
    const octets = match[1].split(".").map(Number);
    if (octets.some((octet) => octet > 255) || Number(match[2]) > 32) {
      return "";
    }
    const bits = 32 - Number(match[2]);
    const mask = bits === 32 ? 0 : (0xffffffff << bits) >>> 0;
    const serverNumber = octets.reduce((result, octet) => ((result << 8) | octet) >>> 0, 0);
    const network = serverNumber & mask;
    const size = 2 ** bits;
    const used = new Set([
      serverNumber,
      ...this.peers.map((peer) => Number(this.ipv4ToInteger(peer.address.split("/")[0]))).filter(Number.isFinite),
    ]);
    for (let host = 1; host < size - 1; host += 1) {
      const candidate = network + host;
      if (!used.has(candidate >>> 0)) {
        return `${this.integerToIpv4(candidate)}${"/32"}`;
      }
    }
    return "";
  }

  ipv4ToInteger(value) {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
      return NaN;
    }
    const octets = value.split(".").map(Number);
    if (octets.some((octet) => octet > 255)) {
      return NaN;
    }
    return octets.reduce((result, octet) => ((result << 8) | octet) >>> 0, 0);
  }

  integerToIpv4(value) {
    return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");
  }

  async generatePeerKeys(peerId) {
    const peer = this.peers.find((candidate) => candidate.id === peerId);
    if (!peer) {
      return;
    }
    try {
      const keys = await this.requestKeyPair();
      peer.privateKey = keys.privateKey;
      peer.publicKey = keys.publicKey;
      this.markDirty();
      this.updatePeersDisplay();
      this.showToast("Peer keys generated successfully.");
    } catch (error) {
      this.showToast(error.message || "Key generation failed. Please sign in again.");
    }
  }

  handlePeerAction(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) {
      return;
    }
    const peerId = Number(button.dataset.peerId);
    switch (button.dataset.action) {
      case "generate":
        this.generatePeerKeys(peerId);
        break;
      case "toggle":
        this.togglePeer(peerId);
        break;
      case "remove":
        this.removePeer(peerId);
        break;
      case "copy-private": {
        const peer = this.peers.find((candidate) => candidate.id === peerId);
        this.copyToClipboard(peer?.privateKey, "Peer private key copied!");
        break;
      }
      case "copy-public": {
        const peer = this.peers.find((candidate) => candidate.id === peerId);
        this.copyToClipboard(peer?.publicKey, "Peer public key copied!");
        break;
      }
      case "download":
        this.downloadPeerConfig(peerId);
        break;
      default:
        break;
    }
  }

  handlePeerChange(event) {
    const input = event.target.closest("[data-field]");
    if (!input) {
      return;
    }
    const peerId = Number(input.dataset.peerId);
    const field = input.dataset.field;
    const value = field === "persistentKeepalive" ? Number(input.value) : input.value;
    const peer = this.peers.find((candidate) => candidate.id === peerId);
    if (!peer) {
      return;
    }
    if (field === "address" && (!peer.serverAllowedIPs || peer.serverAllowedIPs === peer.address)) {
      peer.serverAllowedIPs = value;
    }
    peer[field] = value;
    if (field === "routeMode" && value !== "custom") {
      peer.customAllowedIPs = "";
    }
    this.markDirty();
    this.updatePeersDisplay();
    this.updateConfigOutput();
  }

  removePeer(peerId) {
    this.peers = this.peers.filter((peer) => peer.id !== peerId);
    this.markDirty();
    this.updatePeersDisplay();
    this.updateConfigOutput();
    this.showToast("Peer removed.");
  }

  togglePeer(peerId) {
    const peer = this.peers.find((candidate) => candidate.id === peerId);
    if (peer) {
      peer.enabled = !peer.enabled;
      this.markDirty();
      this.updatePeersDisplay();
      this.updateConfigOutput();
    }
  }

  updatePeer(peerId, field, value) {
    const peer = this.peers.find((candidate) => candidate.id === peerId);
    if (peer) {
      peer[field] = value;
      this.markDirty();
      this.updateConfigOutput();
    }
  }

  updatePeersDisplay() {
    const container = document.getElementById("peersContainer");
    document.getElementById("noPeers").style.display = this.peers.length === 0 ? "block" : "none";
    container.innerHTML = this.peers.map((peer) => this.renderPeer(peer)).join("");
  }

  renderPeer(peer) {
    const id = Number(peer.id);
    const name = this.escapeHtml(peer.name);
    const privateKey = this.escapeHtml(peer.privateKey);
    const publicKey = this.escapeHtml(peer.publicKey);
    const presharedKey = this.escapeHtml(peer.presharedKey || "");
    const address = this.escapeHtml(peer.address);
    const serverAllowedIPs = this.escapeHtml(peer.serverAllowedIPs || peer.address);
    const customAllowedIPs = this.escapeHtml(peer.customAllowedIPs || "");
    const config = this.escapeHtml(peer.config || "Save this network to generate the client config.");
    return `<article class="p-6" data-peer-id="${id}">
      <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div class="flex min-w-0 flex-1 items-center gap-3">
          <input aria-label="Peer name" data-peer-id="${id}" data-field="name" type="text" maxlength="80" value="${name}" class="min-w-0 rounded border border-border bg-input px-2 py-1 text-lg font-semibold">
          <span class="inline-flex items-center rounded-full bg-muted px-2.5 py-0.5 text-xs font-medium text-muted-foreground">${peer.enabled ? "Active" : "Disabled"}</span>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <button data-action="generate" data-peer-id="${id}" class="rounded bg-secondary px-3 py-1 text-sm font-medium text-secondary-foreground hover:bg-secondary/90">Generate keys</button>
          <button data-action="toggle" data-peer-id="${id}" class="rounded bg-muted px-3 py-1 text-sm text-muted-foreground">${peer.enabled ? "Disable" : "Enable"}</button>
          <button data-action="remove" data-peer-id="${id}" class="rounded px-2 py-1 text-sm text-destructive">Remove</button>
        </div>
      </div>
      <div class="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div>
          <label class="mb-2 block text-sm font-medium text-card-foreground">Private key</label>
          <div class="flex gap-2">
            <input aria-label="${name} private key" type="password" value="${privateKey}" readonly class="min-w-0 flex-1 rounded-md border border-border bg-input px-3 py-2 font-mono text-sm" placeholder="Generate keys">
            <button data-action="copy-private" data-peer-id="${id}" class="rounded bg-muted px-3 text-sm text-muted-foreground">Copy</button>
          </div>
        </div>
        <div>
          <label class="mb-2 block text-sm font-medium text-card-foreground">Public key</label>
          <div class="flex gap-2">
            <input aria-label="${name} public key" type="text" value="${publicKey}" readonly class="min-w-0 flex-1 rounded-md border border-border bg-input px-3 py-2 font-mono text-sm" placeholder="Generated with the private key">
            <button data-action="copy-public" data-peer-id="${id}" class="rounded bg-muted px-3 text-sm text-muted-foreground">Copy</button>
          </div>
        </div>
      </div>
      <div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div>
          <label class="mb-2 block text-sm font-medium text-card-foreground">Client VPN address</label>
          <input data-peer-id="${id}" data-field="address" type="text" value="${address}" placeholder="10.0.0.2/32, fd42::2/128" class="w-full rounded-md border border-border bg-input px-3 py-2">
        </div>
        <div>
          <label class="mb-2 block text-sm font-medium text-card-foreground">Server peer AllowedIPs</label>
          <input data-peer-id="${id}" data-field="serverAllowedIPs" type="text" value="${serverAllowedIPs}" class="w-full rounded-md border border-border bg-input px-3 py-2 font-mono text-sm">
        </div>
        <div>
          <label class="mb-2 block text-sm font-medium text-card-foreground">Client routes</label>
          <select data-peer-id="${id}" data-field="routeMode" class="w-full rounded-md border border-border bg-input px-3 py-2">
            <option value="full" ${peer.routeMode === "full" ? "selected" : ""}>Route everything via VPN</option>
            <option value="vpn" ${peer.routeMode === "vpn" ? "selected" : ""}>Route only the VPN subnet</option>
            <option value="custom" ${peer.routeMode === "custom" ? "selected" : ""}>Custom AllowedIPs</option>
          </select>
        </div>
        <div>
          <label class="mb-2 block text-sm font-medium text-card-foreground">Persistent keepalive (seconds)</label>
          <input data-peer-id="${id}" data-field="persistentKeepalive" type="number" min="0" max="65535" value="${Number(peer.persistentKeepalive) || 0}" class="w-full rounded-md border border-border bg-input px-3 py-2">
        </div>
      </div>
      <div class="mt-4">
        <label class="mb-2 block text-sm font-medium text-card-foreground">Preshared key (optional)</label>
        <input data-peer-id="${id}" data-field="presharedKey" type="password" value="${presharedKey}" class="w-full rounded-md border border-border bg-input px-3 py-2 font-mono text-sm">
      </div>
      ${peer.routeMode === "custom" ? `<div class="mt-4"><label class="mb-2 block text-sm font-medium text-card-foreground">Custom AllowedIPs</label><input data-peer-id="${id}" data-field="customAllowedIPs" type="text" value="${customAllowedIPs}" placeholder="10.0.0.0/24, 192.168.1.0/24" class="w-full rounded-md border border-border bg-input px-3 py-2 font-mono text-sm"></div>` : ""}
      <details class="mt-5 border-t border-border pt-4">
        <summary class="cursor-pointer font-medium text-card-foreground">Client config file</summary>
        <textarea readonly class="mt-3 h-40 w-full rounded-md border border-border bg-input px-3 py-2 font-mono text-xs" aria-label="${name} client config">${config}</textarea>
        <button data-action="download" data-peer-id="${id}" ${peer.config ? "" : "disabled"} class="mt-2 rounded bg-secondary px-3 py-2 text-sm font-medium text-secondary-foreground disabled:opacity-50">Download client config</button>
      </details>
    </article>`;
  }

  async refreshNetworks(selectedId = this.networkId) {
    const networks = await this.api("/api/networks");
    const select = document.getElementById("savedNetworks");
    select.replaceChildren(new Option("New network", ""));
    for (const network of networks) {
      select.add(new Option(network.name, network.id));
    }
    select.value = selectedId || "";
  }

  async loadNetwork(id) {
    const network = await this.api(`/api/networks/${encodeURIComponent(id)}`);
    this.applyNetwork(network);
    this.showToast(`Loaded ${network.name}.`);
  }

  applyNetwork(network) {
    this.networkId = network.id;
    this.savedNetwork = network;
    this.dirty = false;
    document.getElementById("networkName").value = network.name;
    document.getElementById("serverInterface").value = network.server?.interfaceName ?? "wg0";
    document.getElementById("serverIP").value = network.server?.address ?? "";
    document.getElementById("serverPort").value = network.server?.listenPort ?? 51820;
    document.getElementById("serverEndpoint").value = network.server?.endpoint ?? "";
    document.getElementById("serverDNS").value = network.server?.dns ?? "";
    this.serverKeys = {
      private: network.server?.privateKey ?? "",
      public: network.server?.publicKey ?? "",
    };
    document.getElementById("serverPrivateKey").value = this.serverKeys.private;
    document.getElementById("serverPublicKey").value = this.serverKeys.public;
    this.peers = (network.peers ?? []).map((peer, index) => ({
      ...peer,
      id: index + 1,
      address: peer.address ?? "",
      serverAllowedIPs: peer.serverAllowedIPs ?? peer.address ?? "",
      routeMode: peer.routeMode ?? "custom",
      customAllowedIPs: peer.customAllowedIPs ?? peer.allowedIPs ?? "",
      persistentKeepalive: Number(peer.persistentKeepalive ?? 25),
      enabled: peer.enabled !== false,
      config: peer.config ?? "",
    }));
    this.peerCounter = this.peers.length;
    document.getElementById("deleteNetwork").disabled = false;
    document.getElementById("savedNetworks").value = network.id;
    document.getElementById("configOutput").value = network.serverConfig ?? "";
    this.updatePeersDisplay();
    this.refreshNetworks(network.id).catch(() => {});
  }

  newNetwork() {
    this.networkId = "";
    this.savedNetwork = null;
    this.dirty = false;
    this.peers = [];
    this.peerCounter = 0;
    this.serverKeys = { private: "", public: "" };
    document.getElementById("networkName").value = "New VPN network";
    document.getElementById("serverInterface").value = "wg0";
    document.getElementById("serverIP").value = "10.0.0.1/24";
    document.getElementById("serverPort").value = "51820";
    document.getElementById("serverEndpoint").value = "";
    document.getElementById("serverDNS").value = "";
    document.getElementById("serverPrivateKey").value = "";
    document.getElementById("serverPublicKey").value = "";
    document.getElementById("savedNetworks").value = "";
    document.getElementById("deleteNetwork").disabled = true;
    this.updatePeersDisplay();
    this.updateConfigOutput();
  }

  async saveNetwork() {
    if (this.networkId && this.savedNetwork && !this.dirty) {
      this.showToast("Network is already saved.");
      return;
    }
    try {
      const payload = this.networkPayload();
      const path = this.networkId ? `/api/networks/${encodeURIComponent(this.networkId)}` : "/api/networks";
      const network = await this.api(path, {
        method: this.networkId ? "PUT" : "POST",
        body: JSON.stringify(payload),
      });
      this.applyNetwork(network);
      await this.refreshNetworks(network.id);
      this.showToast("Network validated and saved.");
    } catch (error) {
      this.showToast(error.message || "Could not save this network.");
    }
  }

  networkPayload() {
    return {
      name: document.getElementById("networkName").value,
      server: {
        interfaceName: document.getElementById("serverInterface").value,
        address: document.getElementById("serverIP").value,
        listenPort: Number(document.getElementById("serverPort").value),
        endpoint: document.getElementById("serverEndpoint").value,
        dns: document.getElementById("serverDNS").value,
        privateKey: this.serverKeys.private,
        publicKey: this.serverKeys.public,
      },
      peers: this.peers.map((peer) => ({
        name: peer.name,
        address: peer.address,
        serverAllowedIPs: peer.serverAllowedIPs || peer.address,
        privateKey: peer.privateKey,
        publicKey: peer.publicKey,
        presharedKey: peer.presharedKey || "",
        routeMode: peer.routeMode,
        customAllowedIPs: peer.customAllowedIPs,
        persistentKeepalive: Number(peer.persistentKeepalive),
        enabled: peer.enabled,
      })),
    };
  }

  async deleteNetwork() {
    if (!this.networkId || !window.confirm(`Delete network “${document.getElementById("networkName").value}”?`)) {
      return;
    }
    try {
      await this.api(`/api/networks/${encodeURIComponent(this.networkId)}`, { method: "DELETE" });
      this.newNetwork();
      await this.refreshNetworks("");
      this.showToast("Network deleted.");
    } catch (error) {
      this.showToast(error.message || "Could not delete this network.");
    }
  }

  async importNetwork() {
    const serverFile = document.getElementById("serverConfigFile").files[0];
    const clientFiles = Array.from(document.getElementById("clientConfigFiles").files);
    if (!serverFile) {
      this.showToast("Choose the server .conf file first.");
      return;
    }
    try {
      const totalBytes = serverFile.size + clientFiles.reduce((size, file) => size + file.size, 0);
      if (totalBytes > 450 * 1024) {
        throw new Error("The selected configs exceed the upload size limit.");
      }
      const payload = {
        name: document.getElementById("networkName").value,
        serverConfig: await serverFile.text(),
        peers: await Promise.all(
          clientFiles.map(async (file, index) => ({
            name: file.name.replace(/\.conf$/i, "") || `Peer ${index + 1}`,
            config: await file.text(),
          })),
        ),
      };
      const validation = await this.api("/api/networks/validate", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      if (!validation.valid) {
        throw new Error("The WireGuard configs did not validate.");
      }
      const network = await this.api("/api/networks/import", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      this.applyNetwork(network);
      await this.refreshNetworks(network.id);
      document.getElementById("serverConfigFile").value = "";
      document.getElementById("clientConfigFiles").value = "";
      this.showToast("Paired configs validated and imported.");
    } catch (error) {
      this.showToast(error.message || "Could not import these configs.");
    }
  }

  markDirty() {
    this.dirty = true;
    this.savedNetwork = null;
    for (const peer of this.peers) {
      peer.config = "";
    }
    this.updatePeersDisplay();
    this.updateConfigOutput();
  }

  updateConfigOutput() {
    if (this.savedNetwork && !this.dirty) {
      document.getElementById("configOutput").value = this.savedNetwork.serverConfig ?? "";
      return;
    }
    const serverIP = document.getElementById("serverIP").value;
    const privateKey = this.serverKeys.private || "[Generate server keys first]";
    const serverPort = document.getElementById("serverPort").value;
    let config = `[Interface]\nAddress = ${serverIP}\nPrivateKey = ${privateKey}\nListenPort = ${serverPort}\n`;
    for (const peer of this.peers.filter(
      (candidate) => candidate.enabled && candidate.publicKey && candidate.address,
    )) {
      config += `\n[Peer]\nPublicKey = ${peer.publicKey}${peer.presharedKey ? `\nPresharedKey = ${peer.presharedKey}` : ""}\nAllowedIPs = ${peer.serverAllowedIPs || peer.address}\n`;
    }
    document.getElementById("configOutput").value = config;
  }

  downloadPeerConfig(peerId) {
    const peer = this.peers.find((candidate) => candidate.id === peerId);
    if (!peer?.config) {
      this.showToast("Save the network to generate its client config.");
      return;
    }
    this.downloadText(peer.config, `${this.fileSlug(peer.name)}.conf`);
  }

  exportConfiguration() {
    const config = document.getElementById("configOutput").value;
    if (!this.savedNetwork || this.dirty) {
      this.showToast("Save the network to validate it before exporting.");
      return;
    }
    this.downloadText(config, `${this.fileSlug(document.getElementById("serverInterface").value || "wg0")}.conf`);
  }

  downloadText(text, filename) {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  fileSlug(value) {
    return (
      value
        .toLowerCase()
        .replace(/[^a-z0-9_-]+/g, "-")
        .replace(/^-+|-+$/g, "") || "wireguard"
    );
  }

  async copyToClipboard(text, message) {
    if (!text) {
      this.showToast("Nothing to copy.");
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      this.showToast(message);
    } catch {
      this.showToast("Clipboard access was denied by this browser.");
    }
  }

  showToast(message) {
    const toast = document.getElementById("toast");
    document.getElementById("toastMessage").textContent = message;
    toast.classList.remove("toast-hidden");
    setTimeout(() => toast.classList.add("toast-hidden"), 3500);
  }

  toggleDarkMode() {
    document.documentElement.classList.toggle("dark");
    localStorage.setItem("darkMode", document.documentElement.classList.contains("dark"));
  }

  escapeHtml(value) {
    return String(value).replace(
      /[&<>"']/g,
      (character) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[character],
    );
  }
}

window.wgManager = new WireGuardManager();
