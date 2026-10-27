import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { createServer } from "node:http";
import { after, before, test } from "node:test";

const issuerKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const issuerPublicJwk = {
  ...issuerKeys.publicKey.export({ format: "jwk" }),
  kid: "integration-test",
  use: "sig",
  alg: "RS256",
};
let issuer;
let issuerServer;
let appUrl;
let appProcess;
let latestNonce;
let tokenRequest;
let appStderr = "";

function sendJson(response, value) {
  response.writeHead(200, { "Content-Type": "application/json" });
  response.end(JSON.stringify(value));
}

function createIdToken(nonce) {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "integration-test", typ: "JWT" })).toString(
    "base64url",
  );
  const payload = Buffer.from(
    JSON.stringify({
      iss: issuer,
      sub: "alice<&",
      aud: "test-client",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      nonce,
    }),
  ).toString("base64url");
  const signingInput = `${header}.${payload}`;
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), issuerKeys.privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

async function unusedPort() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  return port;
}

function startApp(port) {
  return new Promise((resolve, reject) => {
    appProcess = spawn(process.execPath, ["./server/index.ts"], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        NODE_ENV: "test",
        PORT: String(port),
        BASE_URL: appUrl,
        OIDC_ISSUER: issuer,
        OIDC_CLIENT_ID: "test-client",
        OIDC_CLIENT_SECRET: "test-client-secret",
        SESSION_SECRET: "test session secret with at least 32 bytes",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    const startupTimeout = setTimeout(() => reject(new Error(`App failed to start. stderr: ${appStderr}`)), 10_000);
    appProcess.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      if (stdout.includes(`Server started at :${port}`)) {
        clearTimeout(startupTimeout);
        resolve();
      }
    });
    appProcess.stderr.on("data", (chunk) => {
      appStderr += chunk.toString();
    });
    appProcess.once("exit", (code) => {
      clearTimeout(startupTimeout);
      reject(new Error(`App exited before ready (${code}). stderr: ${appStderr}`));
    });
  });
}

before(async () => {
  issuerServer = createServer(async (request, response) => {
    const requestUrl = new URL(request.url, issuer);
    if (request.method === "GET" && requestUrl.pathname === "/.well-known/openid-configuration") {
      sendJson(response, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        end_session_endpoint: `${issuer}/logout`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: ["client_secret_post"],
        code_challenge_methods_supported: ["S256"],
      });
      return;
    }
    if (request.method === "GET" && requestUrl.pathname === "/.well-known/jwks.json") {
      sendJson(response, { keys: [issuerPublicJwk] });
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/token") {
      let body = "";
      for await (const chunk of request) {
        body += chunk;
      }
      tokenRequest = new URLSearchParams(body);
      sendJson(response, {
        access_token: "test-access-token",
        token_type: "Bearer",
        expires_in: 300,
        id_token: createIdToken(latestNonce),
      });
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise((resolve) => issuerServer.listen(0, "127.0.0.1", resolve));
  issuer = `http://127.0.0.1:${issuerServer.address().port}`;
  const port = await unusedPort();
  appUrl = `http://127.0.0.1:${port}`;
  await startApp(port);
});

after(async () => {
  if (appProcess && appProcess.exitCode === null) {
    appProcess.kill("SIGTERM");
    await once(appProcess, "exit");
  }
  if (issuerServer?.listening) {
    await new Promise((resolve, reject) => issuerServer.close((error) => (error ? reject(error) : resolve())));
  }
});

test("X25519 key derivation matches the RFC 7748 test vector", () => {
  const privateBytes = Buffer.from("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "hex");
  const expectedPublicKey = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
  const privateKey = createPrivateKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      d: privateBytes.toString("base64url"),
      x: Buffer.from(expectedPublicKey, "hex").toString("base64url"),
    },
    format: "jwk",
  });
  const publicKey = createPublicKey(privateKey).export({ format: "jwk" });
  assert.equal(Buffer.from(publicKey.x, "base64url").toString("hex"), expectedPublicKey);
});

test("login validates state, PKCE, and nonce before granting the protected session", async () => {
  const homeResponse = await fetch(`${appUrl}/`, { redirect: "manual" });
  assert.equal(homeResponse.status, 302);
  assert.equal(homeResponse.headers.get("location"), "/auth/login");

  const scriptResponse = await fetch(`${appUrl}/index.js`, { redirect: "manual" });
  assert.equal(scriptResponse.status, 302);
  assert.equal(scriptResponse.headers.get("location"), "/auth/login");

  const stylesResponse = await fetch(`${appUrl}/styles.css`, { redirect: "manual" });
  assert.equal(stylesResponse.status, 302);
  assert.equal(stylesResponse.headers.get("location"), "/auth/login");

  const faviconResponse = await fetch(`${appUrl}/favicon.ico`, { redirect: "manual" });
  assert.equal(faviconResponse.status, 302);
  assert.equal(faviconResponse.headers.get("location"), "/auth/login");

  const protectedResponse = await fetch(`${appUrl}/protected`, { redirect: "manual" });
  assert.equal(protectedResponse.status, 302);
  assert.equal(protectedResponse.headers.get("location"), "/auth/login");

  const unknownRoute = await fetch(`${appUrl}/unknown`, { redirect: "manual" });
  assert.equal(unknownRoute.status, 302);
  assert.equal(unknownRoute.headers.get("location"), "/auth/login");

  const callbackWithoutTransaction = await fetch(`${appUrl}/auth/callback`, { redirect: "manual" });
  assert.equal(callbackWithoutTransaction.status, 400);
  assert.doesNotMatch(callbackWithoutTransaction.headers.get("set-cookie") ?? "", /Max-Age=28800/);

  const wrongMethodForLogin = await fetch(`${appUrl}/auth/login`, { method: "POST", redirect: "manual" });
  assert.equal(wrongMethodForLogin.status, 401);

  const logoutFromAnotherOrigin = await fetch(`${appUrl}/auth/logout`, {
    method: "POST",
    headers: { Origin: "https://attacker.example" },
    redirect: "manual",
  });
  assert.equal(logoutFromAnotherOrigin.status, 403);

  const logoutWithoutSession = await fetch(`${appUrl}/auth/logout`, {
    method: "POST",
    headers: { Origin: appUrl },
    redirect: "manual",
  });
  assert.equal(logoutWithoutSession.status, 303);
  assert.equal(logoutWithoutSession.headers.get("location"), `${appUrl}/`);

  const unauthenticatedHealth = await fetch(`${appUrl}/server`, { redirect: "manual" });
  assert.equal(unauthenticatedHealth.status, 401);
  assert.equal(unauthenticatedHealth.headers.get("cache-control"), "no-store");
  assert.deepEqual(await unauthenticatedHealth.json(), { error: "unauthorized", login: "/auth/login" });

  const unauthenticatedKeyGeneration = await fetch(`${appUrl}/api/keys`, { method: "POST" });
  assert.equal(unauthenticatedKeyGeneration.status, 401);
  assert.deepEqual(await unauthenticatedKeyGeneration.json(), { error: "unauthorized", login: "/auth/login" });

  const unauthenticatedApiRoot = await fetch(`${appUrl}/api`, { redirect: "manual" });
  assert.equal(unauthenticatedApiRoot.status, 401);

  const loginResponse = await fetch(`${appUrl}/auth/login`, { redirect: "manual" });
  assert.equal(loginResponse.status, 302);
  const authorizationUrl = new URL(loginResponse.headers.get("location"));
  assert.equal(authorizationUrl.origin, issuer);
  assert.equal(authorizationUrl.searchParams.get("client_id"), "test-client");
  assert.equal(authorizationUrl.searchParams.get("response_type"), "code");
  assert.equal(authorizationUrl.searchParams.get("code_challenge_method"), "S256");
  assert.match(authorizationUrl.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
  assert.equal(authorizationUrl.searchParams.get("redirect_uri"), `${appUrl}/auth/callback`);
  latestNonce = authorizationUrl.searchParams.get("nonce");

  const transactionCookie = loginResponse.headers.get("set-cookie");
  assert.match(transactionCookie, /HttpOnly/);
  assert.match(transactionCookie, /SameSite=Lax/);
  assert.match(transactionCookie, /Max-Age=600/);
  const cookie = transactionCookie.split(";", 1)[0];

  const invalidCallback = await fetch(`${appUrl}/auth/callback?code=test-code&state=wrong`, {
    headers: { Cookie: cookie },
    redirect: "manual",
  });
  assert.equal(invalidCallback.status, 400);

  const callback = await fetch(
    `${appUrl}/auth/callback?code=test-code&state=${encodeURIComponent(authorizationUrl.searchParams.get("state"))}`,
    { headers: { Cookie: cookie }, redirect: "manual" },
  );
  assert.equal(callback.status, 302);
  assert.equal(callback.headers.get("location"), "/");
  assert.equal(tokenRequest.get("redirect_uri"), `${appUrl}/auth/callback`);
  assert.ok(tokenRequest.get("code_verifier"));

  const sessionCookie = callback.headers.get("set-cookie");
  assert.match(sessionCookie, /HttpOnly/);
  assert.match(sessionCookie, /Max-Age=28800/);
  const session = sessionCookie.split(";", 1)[0];
  const home = await fetch(`${appUrl}/`, { headers: { Cookie: session } });
  assert.equal(home.status, 200);
  assert.equal(home.headers.get("cache-control"), "no-store");
  assert.equal(home.headers.get("referrer-policy"), "no-referrer");
  assert.equal(home.headers.get("x-frame-options"), "DENY");
  assert.equal(home.headers.get("cross-origin-resource-policy"), "same-origin");
  const homeHtml = await home.text();
  assert.match(homeHtml, /href="\/styles\.css"/);
  assert.match(homeHtml, /<script src="index\.js"><\/script>/);
  assert.doesNotMatch(homeHtml, /https:\/\/(?:cdn\.tailwindcss\.com|fonts\.googleapis\.com)/);

  const appScript = await fetch(`${appUrl}/index.js`, { headers: { Cookie: session } });
  assert.equal(appScript.status, 200);
  assert.equal(appScript.headers.get("cache-control"), "no-store");
  const appSource = await appScript.text();
  assert.match(appSource, /fetch\("\/api\/keys"/);
  assert.doesNotMatch(appSource, /Math\.random/);

  const stylesheet = await fetch(`${appUrl}/styles.css`, { headers: { Cookie: session } });
  assert.equal(stylesheet.status, 200);
  assert.equal(stylesheet.headers.get("content-type"), "text/css; charset=utf-8");
  assert.match(await stylesheet.text(), /\.bg-background/);

  const signedIn = await fetch(`${appUrl}/protected`, { headers: { Cookie: session } });
  assert.equal(signedIn.status, 200);
  const protectedHtml = await signedIn.text();
  assert.match(protectedHtml, /alice&lt;&amp;/);
  assert.equal(signedIn.headers.get("x-frame-options"), "DENY");
  const csrfToken = protectedHtml.match(/name="csrfToken" value="([A-Za-z0-9_-]+)"/)?.[1];
  assert.ok(csrfToken);

  const authenticatedHealth = await fetch(`${appUrl}/server`, { headers: { Cookie: session } });
  assert.equal(authenticatedHealth.status, 200);
  assert.equal(await authenticatedHealth.text(), "OK");

  const crossOriginKeyGeneration = await fetch(`${appUrl}/api/keys`, {
    method: "POST",
    headers: {
      Cookie: session,
      Origin: "https://attacker.example",
      "Content-Type": "application/json",
    },
    redirect: "manual",
  });
  assert.equal(crossOriginKeyGeneration.status, 403);

  const missingOriginKeyGeneration = await fetch(`${appUrl}/api/keys`, {
    method: "POST",
    headers: { Cookie: session, "Content-Type": "application/json" },
  });
  assert.equal(missingOriginKeyGeneration.status, 403);

  const formKeyGeneration = await fetch(`${appUrl}/api/keys`, {
    method: "POST",
    headers: { Cookie: session, Origin: appUrl, "Content-Type": "application/x-www-form-urlencoded" },
  });
  assert.equal(formKeyGeneration.status, 415);
  assert.deepEqual(await formKeyGeneration.json(), { error: "content_type_must_be_application_json" });

  const generatedKeys = await fetch(`${appUrl}/api/keys`, {
    method: "POST",
    headers: { Cookie: session, Origin: appUrl, "Content-Type": "application/json" },
  });
  assert.equal(generatedKeys.status, 200);
  assert.match(generatedKeys.headers.get("cache-control"), /no-store/);
  assert.equal(generatedKeys.headers.get("cross-origin-resource-policy"), "same-origin");
  const keys = await generatedKeys.json();
  const privateBytes = Buffer.from(keys.privateKey, "base64");
  const publicBytes = Buffer.from(keys.publicKey, "base64");
  assert.equal(privateBytes.length, 32);
  assert.equal(publicBytes.length, 32);
  assert.match(keys.privateKey, /^[A-Za-z0-9+/]{43}=$/);
  assert.match(keys.publicKey, /^[A-Za-z0-9+/]{43}=$/);
  assert.equal(privateBytes.toString("base64"), keys.privateKey);
  assert.equal(publicBytes.toString("base64"), keys.publicKey);
  const privateJwk = createPrivateKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      d: privateBytes.toString("base64url"),
      x: publicBytes.toString("base64url"),
    },
    format: "jwk",
  });
  assert.equal(createPublicKey(privateJwk).export({ format: "jwk" }).x, publicBytes.toString("base64url"));

  const logoutWithoutCsrf = await fetch(`${appUrl}/auth/logout`, {
    method: "POST",
    headers: {
      Cookie: session,
      Origin: appUrl,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "",
    redirect: "manual",
  });
  assert.equal(logoutWithoutCsrf.status, 403);

  const logout = await fetch(`${appUrl}/auth/logout`, {
    method: "POST",
    headers: {
      Cookie: session,
      Origin: appUrl,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ csrfToken }).toString(),
    redirect: "manual",
  });
  assert.equal(logout.status, 303);
  assert.equal(new URL(logout.headers.get("location")).origin, issuer);
  assert.equal(new URL(logout.headers.get("location")).pathname, "/logout");
  assert.match(logout.headers.get("set-cookie"), /Max-Age=0/);

  const signedOut = await fetch(`${appUrl}/protected`, { redirect: "manual" });
  assert.equal(signedOut.status, 302);
});
