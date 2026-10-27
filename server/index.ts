import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import * as oidc from "openid-client";
import { createNetworkStore, generateKeyPair, generateNetworkConfigs, validatePairedConfigs } from "./networks.mjs";

const cookieName = "vpn_session";

function getKey() {
  const secret = process.env.SESSION_SECRET;
  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new Error("SESSION_SECRET must be configured with at least 32 bytes");
  }
  return createHash("sha256").update(secret).digest();
}

function seal(value) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", getKey(), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString("base64url");
}

function unseal(value) {
  if (!value) {
    return;
  }
  try {
    const data = Buffer.from(value, "base64url");
    if (data.length < 29) {
      return;
    }
    const decipher = createDecipheriv("aes-256-gcm", getKey(), data.subarray(0, 12));
    decipher.setAuthTag(data.subarray(12, 28));
    const session = JSON.parse(Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString());
    if (
      !session ||
      typeof session !== "object" ||
      !Number.isFinite(session.createdAt) ||
      session.createdAt > Date.now() ||
      Date.now() - session.createdAt > 8 * 60 * 60 * 1000
    ) {
      return;
    }
    return session;
  } catch {
    return;
  }
}

function cookie(response, value, maxAge, secure) {
  response.setHeader(
    "Set-Cookie",
    `${cookieName}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure ? "; Secure" : ""}`,
  );
}

async function readRequestBody(request, maxBytes = 4096) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) {
      throw Object.assign(new Error("request_body_too_large"), { statusCode: 413 });
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function assertJsonContentType(request) {
  const contentType = request.headers["content-type"];
  if (typeof contentType !== "string" || contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    throw Object.assign(new Error("content_type_must_be_application_json"), { statusCode: 415 });
  }
}

async function readJsonBody(request) {
  assertJsonContentType(request);
  try {
    return JSON.parse(await readRequestBody(request, 1024 * 1024));
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw Object.assign(new Error("invalid_json"), { statusCode: 400 });
    }
    throw error;
  }
}

function sendJson(response, status, value, cacheControl = "no-store") {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": cacheControl,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
  };
  if (status === 401) {
    headers["WWW-Authenticate"] = "OIDC";
  }
  response.writeHead(status, headers);
  response.end(JSON.stringify(value));
}

const signInLanding = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#f4f7f6">
    <title>Sign in to continue</title>
    <style>
      :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
      * { box-sizing: border-box; }
      body { display: grid; min-height: 100vh; margin: 0; place-items: center; background: #f4f7f6; }
      a { padding: 0.9rem 1.5rem; border-radius: 0.5rem; background: #263d32; color: #c8e6a8; font-weight: 600; text-decoration: none; }
      a:hover { background: #1a2a22; }
      a:focus-visible { outline: 3px solid #376d46; outline-offset: 4px; }
      @media (prefers-color-scheme: dark) {
        :root { color-scheme: dark; }
        body { background: #101713; }
        a { background: #376d46; color: #e0f4cf; }
        a:hover { background: #2b4432; }
        a:focus-visible { outline-color: #c8e6a8; }
      }
    </style>
  </head>
  <body><main><a href="/auth/login">Sign in to continue</a></main></body>
</html>`;

async function main() {
  const issuer = process.env.OIDC_ISSUER;
  const clientId = process.env.OIDC_CLIENT_ID;
  const clientSecret = process.env.OIDC_CLIENT_SECRET;
  const baseUrl = process.env.BASE_URL;
  if (!issuer || !clientId || !clientSecret || !baseUrl) {
    throw new Error("OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and BASE_URL are required");
  }
  const appUrl = new URL(baseUrl);
  if (appUrl.username || appUrl.password) {
    throw new Error("BASE_URL must not contain credentials");
  }
  if (!["http:", "https:"].includes(appUrl.protocol) || appUrl.pathname !== "/" || appUrl.search || appUrl.hash) {
    throw new Error("BASE_URL must be an HTTP(S) origin without a path, query, or fragment");
  }
  getKey();
  const issuerUrl = new URL(issuer);
  if (issuerUrl.username || issuerUrl.password || issuerUrl.search || issuerUrl.hash) {
    throw new Error("OIDC_ISSUER must not contain credentials, a query, or a fragment");
  }
  const isLoopbackIssuer = ["localhost", "127.0.0.1", "::1"].includes(issuerUrl.hostname);
  const allowLocalHttp = issuerUrl.protocol === "http:" && isLoopbackIssuer && process.env.NODE_ENV !== "production";
  const config = await oidc.discovery(issuerUrl, clientId, clientSecret, undefined, {
    execute: allowLocalHttp ? [oidc.allowInsecureRequests] : [],
  });
  const callbackUrl = new URL("/auth/callback", appUrl);
  const secureCookie = appUrl.protocol === "https:";
  const [indexPage, app, styles] = await Promise.all([
    readFile("./client/index.html"),
    readFile("./client/index.js"),
    readFile("./client/styles.css"),
  ]);
  const networkStore = createNetworkStore(process.env.NETWORKS_DIR ?? "/home/app/data/networks");

  const server = createServer(async (request, response) => {
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    try {
      const url = new URL(request.url ?? "/", appUrl);
      if (url.origin !== appUrl.origin) {
        throw new Error("Request origin does not match BASE_URL");
      }
      const route = `${request.method} ${url.pathname}`;
      const cookies = Object.fromEntries(
        (request.headers.cookie ?? "")
          .split(";")
          .map((part) => {
            const [name, ...value] = part.trim().split("=");
            return [name, value.join("=")];
          })
          .filter(([name]) => name),
      );
      const session = unseal(cookies[cookieName]);
      const isAuthRoute =
        route === "GET /auth/login" || route === "GET /auth/callback" || route === "POST /auth/logout";

      if (!isAuthRoute && !session?.user) {
        const isApiRequest =
          url.pathname === "/server" ||
          url.pathname === "/api" ||
          url.pathname.startsWith("/api/") ||
          !["GET", "HEAD"].includes(request.method ?? "GET") ||
          request.headers.accept?.includes("application/json");
        if (isApiRequest) {
          sendJson(response, 401, { error: "unauthorized", login: "/auth/login" });
          return;
        }
        if (route === "GET /") {
          response.writeHead(200, {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Content-Security-Policy":
              "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
          });
          response.end(signInLanding);
          return;
        }
        response.writeHead(302, { Location: "/auth/login", "Cache-Control": "no-store" });
        response.end();
        return;
      }

      const isStateChangingRequest = !["GET", "HEAD", "OPTIONS"].includes(request.method ?? "GET");
      const requestOrigin = request.headers.origin;
      const allowsOriginlessLogout = route === "POST /auth/logout" && (!requestOrigin || requestOrigin === "null");
      if (isStateChangingRequest && requestOrigin !== appUrl.origin && !allowsOriginlessLogout) {
        response.writeHead(403, {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        });
        response.end("Cross-origin request rejected");
        return;
      }

      if (route === "GET /auth/login") {
        if (session?.user) {
          response.writeHead(303, { Location: "/", "Cache-Control": "no-store" });
          response.end();
          return;
        }
        const state = oidc.randomState();
        const nonce = oidc.randomNonce();
        const verifier = oidc.randomPKCECodeVerifier();
        const challenge = await oidc.calculatePKCECodeChallenge(verifier);
        const scopes = new Set((process.env.OIDC_SCOPE ?? "openid profile email").split(/\s+/).filter(Boolean));
        scopes.add("openid");
        const authorizationUrl = oidc.buildAuthorizationUrl(config, {
          redirect_uri: callbackUrl.href,
          scope: [...scopes].join(" "),
          response_type: "code",
          state,
          nonce,
          code_challenge: challenge,
          code_challenge_method: "S256",
        });
        cookie(
          response,
          seal({ type: "oidc_transaction", state, nonce, verifier, createdAt: Date.now() }),
          600,
          secureCookie,
        );
        response.writeHead(302, { Location: authorizationUrl.href, "Cache-Control": "no-store" });
        response.end();
        return;
      }

      if (route === "GET /auth/callback") {
        if (
          session?.type !== "oidc_transaction" ||
          !session.state ||
          !session.nonce ||
          !session.verifier ||
          Date.now() - session.createdAt > 10 * 60 * 1000
        ) {
          throw new Error("Missing authorization transaction");
        }
        const tokens = await oidc.authorizationCodeGrant(
          config,
          url,
          {
            pkceCodeVerifier: session.verifier,
            expectedState: session.state,
            expectedNonce: session.nonce,
          },
          { redirect_uri: callbackUrl.href },
        );
        const claims = tokens.claims();
        cookie(
          response,
          seal({
            user: claims?.sub ?? "Authenticated user",
            idToken: tokens.id_token,
            csrfToken: randomBytes(32).toString("base64url"),
            createdAt: Date.now(),
          }),
          8 * 60 * 60,
          secureCookie,
        );
        response.writeHead(302, { Location: "/", "Cache-Control": "no-store" });
        response.end();
        return;
      }

      if (route === "POST /auth/logout") {
        if (session?.user && session.csrfToken) {
          const contentType = request.headers["content-type"];
          if (
            typeof contentType !== "string" ||
            contentType.split(";", 1)[0].trim().toLowerCase() !== "application/x-www-form-urlencoded"
          ) {
            response.writeHead(415, {
              "Content-Type": "text/plain; charset=utf-8",
              "Cache-Control": "no-store",
              "X-Content-Type-Options": "nosniff",
            });
            response.end("Expected a form-encoded logout request");
            return;
          }
          const form = new URLSearchParams(await readRequestBody(request));
          if (form.get("csrfToken") !== session.csrfToken) {
            response.writeHead(403, {
              "Content-Type": "text/plain; charset=utf-8",
              "Cache-Control": "no-store",
              "X-Content-Type-Options": "nosniff",
            });
            response.end("Invalid logout request");
            return;
          }
        }
        cookie(response, "", 0, secureCookie);
        const endSessionEndpoint = config.serverMetadata().end_session_endpoint;
        const logoutUrl =
          session?.idToken && endSessionEndpoint
            ? oidc.buildEndSessionUrl(config, {
                id_token_hint: session.idToken,
                post_logout_redirect_uri: appUrl.href,
              })
            : appUrl;
        response.writeHead(303, { Location: logoutUrl.href, "Cache-Control": "no-store" });
        response.end();
        return;
      }

      switch (route) {
        case "GET /": {
          const authenticatedIndex = indexPage
            .toString()
            .replace('value="__CSRF_TOKEN__"', `value="${escapeHtml(session.csrfToken ?? "")}"`);
          response.writeHead(200, {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
          });
          response.end(authenticatedIndex);
          return;
        }
        case "GET /index.js":
          response.writeHead(200, {
            "Content-Type": "text/javascript; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
          });
          response.end(app);
          return;
        case "GET /styles.css":
          response.writeHead(200, {
            "Content-Type": "text/css; charset=utf-8",
            "Cache-Control": "no-store",
          });
          response.end(styles);
          return;
        case "GET /server":
          response.writeHead(200, {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "no-store",
          });
          response.end("OK");
          return;
        case "POST /api/keys": {
          assertJsonContentType(request);
          sendJson(response, 200, generateKeyPair(), "no-store, private");
          return;
        }
        default:
          break;
      }

      if (route === "GET /api/networks") {
        sendJson(response, 200, await networkStore.list());
        return;
      }

      if (route === "POST /api/networks") {
        const network = generateNetworkConfigs(await readJsonBody(request));
        sendJson(response, 201, await networkStore.save(network));
        return;
      }

      if (route === "POST /api/networks/validate") {
        const body = await readJsonBody(request);
        const network = body.serverConfig ? validatePairedConfigs(body) : generateNetworkConfigs(body);
        sendJson(response, 200, { valid: true, name: network.name, peerCount: network.peers.length });
        return;
      }

      if (route === "POST /api/networks/import") {
        const network = validatePairedConfigs(await readJsonBody(request));
        sendJson(response, 201, await networkStore.save(network));
        return;
      }

      const networkDetailMatch = route.match(/^GET \/api\/networks\/([a-z0-9]+(?:-[a-z0-9]+)*)$/);
      if (networkDetailMatch) {
        try {
          sendJson(response, 200, await networkStore.get(networkDetailMatch[1]));
        } catch (error) {
          if (error?.code === "ENOENT") {
            sendJson(response, 404, { error: "network_not_found" });
            return;
          }
          throw error;
        }
        return;
      }

      const networkUpdateMatch = route.match(/^PUT \/api\/networks\/([a-z0-9]+(?:-[a-z0-9]+)*)$/);
      if (networkUpdateMatch) {
        const network = generateNetworkConfigs(await readJsonBody(request));
        try {
          sendJson(response, 200, await networkStore.save(network, networkUpdateMatch[1]));
        } catch (error) {
          if (error?.code === "ENOENT") {
            sendJson(response, 404, { error: "network_not_found" });
            return;
          }
          throw error;
        }
        return;
      }

      const networkDeleteMatch = route.match(/^DELETE \/api\/networks\/([a-z0-9]+(?:-[a-z0-9]+)*)$/);
      if (networkDeleteMatch) {
        try {
          await networkStore.remove(networkDeleteMatch[1]);
        } catch (error) {
          if (error?.code === "ENOENT") {
            sendJson(response, 404, { error: "network_not_found" });
            return;
          }
          throw error;
        }
        sendJson(response, 200, { deleted: true });
        return;
      }
      response.writeHead(404, { "Cache-Control": "no-store" });
      response.end();
    } catch (error) {
      const requestPath = (request.url ?? "/").split("?", 1)[0];
      if (requestPath === "/api" || requestPath.startsWith("/api/")) {
        const statusCode = error?.statusCode ?? (error?.code ? 500 : 400);
        if (statusCode >= 500) {
          console.error("API request failed", error?.code ?? "unknown error");
        }
        sendJson(response, statusCode, {
          error: statusCode >= 500 ? "internal_error" : (error?.message ?? "request_failed"),
        });
        return;
      }
      console.error("Request failed", error instanceof Error ? error.message : "unknown error");
      response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
      response.end("Authentication request failed");
    }
  });

  server.listen(Number(process.env.PORT ?? 3000), () => {
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : (process.env.PORT ?? 3000);
    console.log(`Server started at :${port}`);
  });
}

function escapeHtml(value) {
  return value.replace(
    /[&<>"']/g,
    (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character],
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
