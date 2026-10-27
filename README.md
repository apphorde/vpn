# VPN manager for Wireguard

## OIDC protection

The main UI, static JavaScript, health route, and API routes require an OpenID Connect login. Unauthenticated page requests redirect to sign-in; API requests return `401`. Only the OIDC login, callback, and logout routes are public. Configure the following environment variables before starting the server:

- `OIDC_ISSUER`: the issuer URL used for OpenID Connect discovery.
- `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`: credentials for a confidential OIDC client.
- `BASE_URL`: the app's public HTTP(S) origin, such as `https://vpn.example.com`. Register `${BASE_URL}/auth/callback` as its redirect URI and `${BASE_URL}/` as its post-logout redirect URI.
- `SESSION_SECRET`: a secret of at least 32 bytes used to encrypt the HttpOnly session cookie.
- `OIDC_SCOPE` (optional): requested scopes; defaults to `openid profile email`.
- `PORT` (optional): server port; defaults to `3000`.

The sign-in flow uses authorization code + PKCE with state and nonce checks. The session cookie is encrypted, HttpOnly, and SameSite=Lax, and is marked Secure when `BASE_URL` uses HTTPS. Signing out requires a session-bound CSRF token, clears the local session, and ends the identity-provider session when the provider advertises an end-session endpoint.

The UI requests WireGuard X25519 key pairs from `POST /api/keys`. This endpoint requires an authenticated session, an exact same-origin `Origin` header, and a JSON content type. It returns non-cacheable 32-byte WireGuard keys and does not persist them on the server. The private key is delivered to the signed-in browser over HTTPS; use the generated configuration only after reviewing it.

The UI stylesheet is built locally and served behind the same OIDC gate; no third-party JavaScript or fonts are loaded. Run `npm run build:css` after changing UI classes so the generated stylesheet stays current.
