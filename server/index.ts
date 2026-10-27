import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createCipheriv, createDecipheriv, createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import * as oidc from "openid-client";

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

async function readRequestBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 4096) {
      throw new Error("Request body is too large");
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

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
          response.writeHead(401, {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
            "WWW-Authenticate": "OIDC",
          });
          response.end(JSON.stringify({ error: "unauthorized", login: "/auth/login" }));
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

      if (route === "GET /protected") {
        if (!session?.user) {
          response.writeHead(302, { Location: "/auth/login" });
          response.end();
          return;
        }
        response.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
          "Referrer-Policy": "no-referrer",
        });
        response.end(
          `<main><h1>Protected area</h1><p>Signed in as ${escapeHtml(session.user)}</p><form method="post" action="/auth/logout"><input type="hidden" name="csrfToken" value="${escapeHtml(session.csrfToken ?? "")}"><button>Sign out</button></form><p><a href="/">Return to WireGuard Manager</a></p></main>`,
        );
        return;
      }

      switch (route) {
        case "GET /":
          response.writeHead(200, {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
          });
          response.end(indexPage);
          return;
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
          if (request.headers.origin !== appUrl.origin) {
            response.writeHead(403, {
              "Content-Type": "application/json; charset=utf-8",
              "Cache-Control": "no-store",
              "X-Content-Type-Options": "nosniff",
            });
            response.end(JSON.stringify({ error: "same_origin_required" }));
            return;
          }
          const contentType = request.headers["content-type"];
          if (
            typeof contentType !== "string" ||
            contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json"
          ) {
            response.writeHead(415, {
              "Content-Type": "application/json; charset=utf-8",
              "Cache-Control": "no-store",
              "X-Content-Type-Options": "nosniff",
            });
            response.end(JSON.stringify({ error: "content_type_must_be_application_json" }));
            return;
          }
          const { privateKey, publicKey } = generateKeyPairSync("x25519");
          const privateJwk = privateKey.export({ format: "jwk" });
          const publicJwk = publicKey.export({ format: "jwk" });
          response.writeHead(200, {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store, private",
            Pragma: "no-cache",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cross-Origin-Resource-Policy": "same-origin",
          });
          response.end(
            JSON.stringify({
              privateKey: Buffer.from(privateJwk.d, "base64url").toString("base64"),
              publicKey: Buffer.from(publicJwk.x, "base64url").toString("base64"),
            }),
          );
          return;
        }
        default:
          response.writeHead(404);
          response.end();
          return;
      }
    } catch (error) {
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
