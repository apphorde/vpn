# VPN manager for Wireguard

## OIDC protected area

The `/protected` page requires an OpenID Connect login. Configure the following environment variables before starting the server:

- `OIDC_ISSUER`: the issuer URL used for OpenID Connect discovery.
- `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`: credentials for a confidential OIDC client.
- `BASE_URL`: the app's public HTTP(S) origin, such as `https://vpn.example.com`. Register `${BASE_URL}/auth/callback` as its redirect URI and `${BASE_URL}/` as its post-logout redirect URI.
- `SESSION_SECRET`: a secret of at least 32 bytes used to encrypt the HttpOnly session cookie.
- `OIDC_SCOPE` (optional): requested scopes; defaults to `openid profile email`.
- `PORT` (optional): server port; defaults to `3000`.

The sign-in flow uses authorization code + PKCE with state and nonce checks. The session cookie is encrypted, HttpOnly, and SameSite=Lax, and is marked Secure when `BASE_URL` uses HTTPS. Signing out clears the local session and ends the identity-provider session when the provider advertises an end-session endpoint.
