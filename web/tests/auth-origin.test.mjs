import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test, { after, afterEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["auth-edge"]);
const { hasTrustedOrigin } = await import(compiled.url("auth-edge"));
const previous = process.env.HCP_TRUSTED_TLS_PROXY;
afterEach(() => {
  if (previous === undefined) delete process.env.HCP_TRUSTED_TLS_PROXY;
  else process.env.HCP_TRUSTED_TLS_PROXY = previous;
});
after(() => rmSync(compiled.directory, { recursive: true, force: true }));

const request = (headers) => ({
  headers: new Headers({ host: "localhost:3000", ...headers }),
  nextUrl: { origin: "http://localhost:3000" },
});

test("untrusted forwarded headers cannot authorize a foreign Origin or Referer", () => {
  for (const value of [undefined, "false"]) {
    if (value === undefined) delete process.env.HCP_TRUSTED_TLS_PROXY;
    else process.env.HCP_TRUSTED_TLS_PROXY = value;
    const forwarded = { "x-forwarded-host": "foreign.invalid", "x-forwarded-proto": "https" };
    assert.equal(hasTrustedOrigin(request({ ...forwarded, origin: "https://foreign.invalid" })), false);
    assert.equal(hasTrustedOrigin(request({ ...forwarded, referer: "https://foreign.invalid/page" })), false);
    assert.equal(hasTrustedOrigin(request({ ...forwarded, origin: "http://localhost:3000" })), true);
  }
});

test("explicit trusted TLS proxy authorizes its public origin and rejects others", () => {
  process.env.HCP_TRUSTED_TLS_PROXY = "true";
  const forwarded = { "x-forwarded-host": "hcp.example", "x-forwarded-proto": "https" };
  assert.equal(hasTrustedOrigin(request({ ...forwarded, origin: "https://hcp.example" })), true);
  assert.equal(hasTrustedOrigin(request({ ...forwarded, referer: "https://hcp.example/hosts" })), true);
  assert.equal(hasTrustedOrigin(request({ ...forwarded, origin: "https://foreign.invalid" })), false);
  assert.equal(hasTrustedOrigin(request({ ...forwarded, origin: "http://localhost:3000" })), false);
});

test("ambiguous proxy authorities and non-HTTP schemes fail closed", () => {
  process.env.HCP_TRUSTED_TLS_PROXY = "true";
  for (const host of ["hcp.example, foreign.invalid", "user@hcp.example", "hcp.example/path", "hcp.example#fragment", "hcp.example\\foreign.invalid"]) {
    assert.equal(hasTrustedOrigin(request({ "x-forwarded-host": host, "x-forwarded-proto": "https", origin: "https://hcp.example" })), false);
  }
  for (const protocol of ["https,http", "file", "javascript"]) {
    assert.equal(hasTrustedOrigin(request({ "x-forwarded-host": "hcp.example", "x-forwarded-proto": protocol, origin: "https://hcp.example" })), false);
  }
});

test("direct requests require a matching Origin or a valid matching Referer", () => {
  delete process.env.HCP_TRUSTED_TLS_PROXY;
  assert.equal(hasTrustedOrigin(request({ origin: "http://localhost:3000" })), true);
  assert.equal(hasTrustedOrigin(request({ referer: "http://localhost:3000/hosts" })), true);
  for (const headers of [{}, { origin: "null" }, { origin: "https://foreign.invalid", referer: "http://localhost:3000/hosts" }, { referer: "invalid" }]) {
    assert.equal(hasTrustedOrigin(request(headers)), false);
  }
});

test("production HTTP backend ignores a scheme already rewritten by Next from forwarded proto", () => {
  const previousMode = process.env.NODE_ENV;
  delete process.env.HCP_TRUSTED_TLS_PROXY;
  process.env.NODE_ENV = "production";
  try {
    const rewritten = (origin) => ({
      headers: new Headers({ host: "localhost:3000", "x-forwarded-proto": "https", origin }),
      nextUrl: { origin: "https://localhost:3000" },
    });
    assert.equal(hasTrustedOrigin(rewritten("https://localhost:3000")), false);
    assert.equal(hasTrustedOrigin(rewritten("http://localhost:3000")), true);
  } finally {
    if (previousMode === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousMode;
  }
});
