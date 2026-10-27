import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { generateKeyPairSync, sign } from "node:crypto";
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

test("login validates state, PKCE, and nonce before granting the protected session", async () => {
  const protectedResponse = await fetch(`${appUrl}/protected`, { redirect: "manual" });
  assert.equal(protectedResponse.status, 302);
  assert.equal(protectedResponse.headers.get("location"), "/auth/login");

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
  assert.equal(callback.headers.get("location"), "/protected");
  assert.equal(tokenRequest.get("redirect_uri"), `${appUrl}/auth/callback`);
  assert.ok(tokenRequest.get("code_verifier"));

  const sessionCookie = callback.headers.get("set-cookie");
  assert.match(sessionCookie, /HttpOnly/);
  assert.match(sessionCookie, /Max-Age=28800/);
  const session = sessionCookie.split(";", 1)[0];
  const signedIn = await fetch(`${appUrl}/protected`, { headers: { Cookie: session } });
  assert.equal(signedIn.status, 200);
  assert.match(await signedIn.text(), /alice&lt;&amp;/);

  const logout = await fetch(`${appUrl}/auth/logout`, {
    method: "POST",
    headers: { Cookie: session },
    redirect: "manual",
  });
  assert.equal(logout.status, 303);
  assert.equal(new URL(logout.headers.get("location")).origin, issuer);
  assert.equal(new URL(logout.headers.get("location")).pathname, "/logout");
  assert.match(logout.headers.get("set-cookie"), /Max-Age=0/);

  const signedOut = await fetch(`${appUrl}/protected`, { redirect: "manual" });
  assert.equal(signedOut.status, 302);
});
