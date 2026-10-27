# VPN manager for Wireguard

## OIDC protection

The main UI, static JavaScript, health route, and API routes require an OpenID Connect login. An unauthenticated request to `/` shows only a centered **Sign in to continue** button; protected assets redirect to the OIDC login and APIs return `401`. Only that small landing page and the OIDC login/callback/logout routes are public. Configure the following environment variables before starting the server:

- `OIDC_ISSUER`: the issuer URL used for OpenID Connect discovery.
- `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`: credentials for a confidential OIDC client.
- `BASE_URL`: the app's public HTTP(S) origin, such as `https://vpn.example.com`. Register `${BASE_URL}/auth/callback` as its redirect URI and `${BASE_URL}/` as its post-logout redirect URI.
- `SESSION_SECRET`: a secret of at least 32 bytes used to encrypt the HttpOnly session cookie.
- `OIDC_SCOPE` (optional): requested scopes; defaults to `openid profile email`.
- `PORT` (optional): server port; defaults to `3000`.
- `NETWORKS_DIR` (optional): directory for saved network files; defaults to `/home/app/data/networks`, under the app's mounted data volume.

The sign-in flow uses authorization code + PKCE with state and nonce checks. The session cookie is encrypted, HttpOnly, and SameSite=Lax, and is marked Secure when `BASE_URL` uses HTTPS. Signing out requires a session-bound CSRF token, clears the local session, and ends the identity-provider session when the provider advertises an end-session endpoint.

The UI requests WireGuard X25519 key pairs from `POST /api/keys`. Key generation requires an authenticated session, an exact same-origin `Origin` header, and a JSON content type. Generated keys stay in the browser until a network is saved. Saving creates `/home/app/data/networks/<network-id>/server.conf`, one `peers/*.conf` file per client, and a `network.json` manifest; config and manifest files use mode `0600`. These files contain private keys. Protect the mounted volume and backups accordingly. The authenticated network API can list names, load, update, delete, validate, and import networks. `POST /api/networks/validate` validates generated network data or paired configs without saving; `POST /api/networks/import` imports one server `.conf` plus the matching client `.conf` files.

Each generated peer config gets client `AllowedIPs` from its route selection: full tunnel (`0.0.0.0/0, ::/0`), the server VPN subnets, or explicitly entered custom CIDRs. By default, server peer routes cover only each client's VPN address; imported and explicitly edited server-side routes are preserved. Imports are stored as supplied after validation; saving later edits rebuilds configs from the manager's fields, so other imported directives and hooks are not retained. Review imported `PreUp`/`PostUp`/`PreDown`/`PostDown` shell commands before using those files with `wg-quick`; this app never executes them. Import checks that client private keys derive the matching server peer public keys, that each client points back to the server public key, and that VPN addresses and routes are valid. The built-in validator checks supported WireGuard/wg-quick directives, key pairs, addresses, endpoints, ports, and peer pairing; it does not invoke `wg`/`wg-quick` or bring up interfaces. Network activation is intentionally not implemented yet.

The UI stylesheet is built locally and served behind the same OIDC gate; no third-party JavaScript or fonts are loaded. Run `npm run build:css` after changing UI classes so the generated stylesheet stays current.
