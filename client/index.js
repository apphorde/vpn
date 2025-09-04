class WireGuardManager {
  constructor() {
    this.peers = [];
    this.peerCounter = 0;
    this.serverKeys = { private: "", public: "" };
    this.init();
  }

  init() {
    this.bindEvents();
    this.updatePeersDisplay();
    this.updateConfigOutput();
  }

  bindEvents() {
    // Server key generation
    document
      .getElementById("generateServerKeys")
      .addEventListener("click", () => {
        this.generateServerKeys();
      });

    // Copy buttons
    document
      .getElementById("copyServerPrivate")
      .addEventListener("click", () => {
        this.copyToClipboard(
          document.getElementById("serverPrivateKey").value,
          "Server private key copied!"
        );
      });

    document
      .getElementById("copyServerPublic")
      .addEventListener("click", () => {
        this.copyToClipboard(
          document.getElementById("serverPublicKey").value,
          "Server public key copied!"
        );
      });

    // Add peer
    document.getElementById("addPeer").addEventListener("click", () => {
      this.addPeer();
    });

    // Export configuration
    document.getElementById("exportConfig").addEventListener("click", () => {
      this.exportConfiguration();
    });

    // Dark mode toggle
    document.getElementById("darkModeToggle").addEventListener("click", () => {
      this.toggleDarkMode();
    });

    // Server configuration changes
    ["serverPort", "serverInterface", "serverIP"].forEach((id) => {
      document.getElementById(id).addEventListener("input", () => {
        this.updateConfigOutput();
      });
    });
  }

  generateServerKeys() {
    // Simulate key generation (in real implementation, use proper crypto library)
    const privateKey = this.generateRandomKey();
    const publicKey = this.derivePublicKey(privateKey);

    this.serverKeys = { private: privateKey, public: publicKey };

    document.getElementById("serverPrivateKey").value = privateKey;
    document.getElementById("serverPublicKey").value = publicKey;

    this.updateConfigOutput();
    this.showToast("Server keys generated successfully!");
  }

  generateRandomKey() {
    // Simulate WireGuard key generation (44 characters, base64)
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let result = "";
    for (let i = 0; i < 43; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result + "=";
  }

  derivePublicKey(privateKey) {
    // Simulate public key derivation (in real implementation, use proper crypto)
    return this.generateRandomKey();
  }

  addPeer() {
    const peer = {
      id: ++this.peerCounter,
      name: `Peer ${this.peerCounter}`,
      privateKey: "",
      publicKey: "",
      allowedIPs: `10.0.0.${this.peerCounter + 1}/32`,
      endpoint: "",
      persistentKeepalive: 25,
      enabled: true,
    };

    this.peers.push(peer);
    this.updatePeersDisplay();
    this.updateConfigOutput();
  }

  removePeer(peerId) {
    this.peers = this.peers.filter((peer) => peer.id !== peerId);
    this.updatePeersDisplay();
    this.updateConfigOutput();
    this.showToast("Peer removed successfully!");
  }

  generatePeerKeys(peerId) {
    const peer = this.peers.find((p) => p.id === peerId);
    if (peer) {
      peer.privateKey = this.generateRandomKey();
      peer.publicKey = this.derivePublicKey(peer.privateKey);
      this.updatePeersDisplay();
      this.updateConfigOutput();
      this.showToast("Peer keys generated successfully!");
    }
  }

  updatePeer(peerId, field, value) {
    const peer = this.peers.find((p) => p.id === peerId);
    if (peer) {
      peer[field] = value;
      this.updateConfigOutput();
    }
  }

  updatePeersDisplay() {
    const container = document.getElementById("peersContainer");
    const noPeers = document.getElementById("noPeers");

    if (this.peers.length === 0) {
      container.innerHTML = "";
      noPeers.style.display = "block";
      return;
    }

    noPeers.style.display = "none";
    container.innerHTML = this.peers
      .map((peer) => this.renderPeer(peer))
      .join("");

    // Bind events for peer controls
    this.peers.forEach((peer) => {
      this.bindPeerEvents(peer.id);
    });
  }

  renderPeer(peer) {
    return `
            <div class="p-6" data-peer-id="${peer.id}">
                <div class="flex items-center justify-between mb-4">
                    <div class="flex items-center space-x-3">
                        <input type="text" value="${peer.name}"
                               class="text-lg font-heading font-semibold bg-transparent border-none p-0 focus:outline-none focus:ring-2 focus:ring-ring rounded"
                               onchange="wgManager.updatePeer(${
                                 peer.id
                               }, 'name', this.value)">
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          peer.enabled
                            ? "bg-muted text-muted-foreground"
                            : "bg-destructive/10 text-destructive"
                        }">
                            ${peer.enabled ? "Active" : "Disabled"}
                        </span>
                    </div>
                    <div class="flex items-center space-x-2">
                        <button onclick="wgManager.generatePeerKeys(${peer.id})"
                                class="bg-secondary text-secondary-foreground px-3 py-1 rounded text-sm hover:bg-secondary/90 transition-colors">
                            Generate Keys
                        </button>
                        <button onclick="wgManager.togglePeer(${peer.id})"
                                class="p-2 text-muted-foreground hover:text-foreground transition-colors">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${
                                  peer.enabled
                                    ? "M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21"
                                    : "M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                                }"></path>
                            </svg>
                        </button>
                        <button onclick="wgManager.removePeer(${peer.id})"
                                class="p-2 text-destructive hover:text-destructive/80 transition-colors">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                            </svg>
                        </button>
                    </div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
                    <div>
                        <label class="block text-sm font-medium text-card-foreground mb-2">Private Key</label>
                        <div class="relative">
                            <input type="text" value="${peer.privateKey}"
                                   class="w-full px-3 py-2 bg-input border border-border rounded-md font-mono text-sm"
                                   placeholder="Generate keys to create private key"
                                   onchange="wgManager.updatePeer(${
                                     peer.id
                                   }, 'privateKey', this.value)">
                            <button onclick="wgManager.copyToClipboard('${
                              peer.privateKey
                            }', 'Private key copied!')"
                                    class="absolute right-2 top-2 p-1 text-muted-foreground hover:text-foreground transition-colors">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                                </svg>
                            </button>
                        </div>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-card-foreground mb-2">Public Key</label>
                        <div class="relative">
                            <input type="text" value="${peer.publicKey}"
                                   class="w-full px-3 py-2 bg-input border border-border rounded-md font-mono text-sm"
                                   placeholder="Public key will appear here" readonly>
                            <button onclick="wgManager.copyToClipboard('${
                              peer.publicKey
                            }', 'Public key copied!')"
                                    class="absolute right-2 top-2 p-1 text-muted-foreground hover:text-foreground transition-colors">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                                </svg>
                            </button>
                        </div>
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-card-foreground mb-2">Allowed IPs</label>
                        <input type="text" value="${peer.allowedIPs}"
                               class="w-full px-3 py-2 bg-input border border-border rounded-md"
                               onchange="wgManager.updatePeer(${
                                 peer.id
                               }, 'allowedIPs', this.value)">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-card-foreground mb-2">Endpoint</label>
                        <input type="text" value="${peer.endpoint}"
                               class="w-full px-3 py-2 bg-input border border-border rounded-md"
                               placeholder="server.example.com:51820"
                               onchange="wgManager.updatePeer(${
                                 peer.id
                               }, 'endpoint', this.value)">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-card-foreground mb-2">Persistent Keepalive</label>
                        <input type="number" value="${peer.persistentKeepalive}"
                               class="w-full px-3 py-2 bg-input border border-border rounded-md"
                               min="0" max="65535"
                               onchange="wgManager.updatePeer(${
                                 peer.id
                               }, 'persistentKeepalive', parseInt(this.value))">
                    </div>
                </div>
            </div>
        `;
  }

  bindPeerEvents(peerId) {
    // Events are bound inline in the HTML for simplicity
  }

  togglePeer(peerId) {
    const peer = this.peers.find((p) => p.id === peerId);
    if (peer) {
      peer.enabled = !peer.enabled;
      this.updatePeersDisplay();
      this.updateConfigOutput();
      this.showToast(`Peer ${peer.enabled ? "enabled" : "disabled"}!`);
    }
  }

  updateConfigOutput() {
    const serverPort = document.getElementById("serverPort").value;
    const serverInterface = document.getElementById("serverInterface").value;
    const serverIP = document.getElementById("serverIP").value;

    let config = `[Interface]
Address = ${serverIP}
PrivateKey = ${this.serverKeys.private || "[Generate server keys first]"}
ListenPort = ${serverPort}

`;

    this.peers
      .filter((peer) => peer.enabled && peer.publicKey)
      .forEach((peer) => {
        config += `[Peer]
# ${peer.name}
PublicKey = ${peer.publicKey}
AllowedIPs = ${peer.allowedIPs}
`;
        if (peer.endpoint) {
          config += `Endpoint = ${peer.endpoint}
`;
        }
        if (peer.persistentKeepalive > 0) {
          config += `PersistentKeepalive = ${peer.persistentKeepalive}
`;
        }
        config += "\n";
      });

    document.getElementById("configOutput").value = config;
  }

  exportConfiguration() {
    const config = document.getElementById("configOutput").value;
    if (!config.trim()) {
      this.showToast("No configuration to export!");
      return;
    }

    const blob = new Blob([config], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "wg0.conf";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    this.showToast("Configuration exported successfully!");
  }

  copyToClipboard(text, message) {
    if (!text) {
      this.showToast("Nothing to copy!");
      return;
    }

    navigator.clipboard
      .writeText(text)
      .then(() => {
        this.showToast(message);
      })
      .catch(() => {
        // Fallback for older browsers
        const textArea = document.createElement("textarea");
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand("copy");
        document.body.removeChild(textArea);
        this.showToast(message);
      });
  }

  showToast(message) {
    const toast = document.getElementById("toast");
    const toastMessage = document.getElementById("toastMessage");

    toastMessage.textContent = message;
    toast.classList.remove("translate-x-full");

    setTimeout(() => {
      toast.classList.add("translate-x-full");
    }, 3000);
  }

  toggleDarkMode() {
    document.documentElement.classList.toggle("dark");
    localStorage.setItem(
      "darkMode",
      document.documentElement.classList.contains("dark")
    );
  }
}

// Initialize the application
const wgManager = new WireGuardManager();

// Load dark mode preference
if (localStorage.getItem("darkMode") === "true") {
  document.documentElement.classList.add("dark");
}
