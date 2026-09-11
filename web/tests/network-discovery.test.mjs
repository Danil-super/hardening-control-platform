import assert from "node:assert/strict";
import { after, test } from "node:test";
import { rmSync } from "node:fs";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["network-discovery"]);
const { buildNetworkSuggestions, listHosts, parseCidr } = await import(compiled.url("network-discovery"));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));
const input = { routes: "", inContainer: false, targetAddress: "", siteHostname: "localhost", interfaces: [] };

test("successful detection always includes ok and normalizes the network", () => {
  const result = buildNetworkSuggestions({ ...input, routes: "192.168.56.0/24 dev enp0s8 proto kernel scope link src 192.168.56.4" });
  assert.equal(result.ok, true);
  assert.equal(result.defaultCidr, "192.168.56.0/24");
  assert.equal(result.candidates[0].origin, "interface");
});

test("Docker bridge is labeled and never chosen automatically as the Astra network", () => {
  for (const inContainer of [true, false]) {
    const result = buildNetworkSuggestions({ ...input, inContainer,
      routes: `172.18.0.0/16 dev ${inContainer ? "eth0" : "docker0"} proto kernel scope link src 172.18.0.1` });
    assert.equal(result.ok, true);
    assert.equal(result.defaultCidr, "");
    assert.equal(result.candidates[0].origin, "container");
    assert.equal(result.candidates[0].cidr, "172.18.0.0/24");
  }
});

test("target and site addresses provide explicitly approximate /24 suggestions in Docker", () => {
  const result = buildNetworkSuggestions({ ...input, inContainer: true, targetAddress: "172.16.95.128", siteHostname: "192.168.1.5" });
  assert.equal(result.defaultCidr, "172.16.95.0/24");
  assert.equal(result.candidates[0].origin, "target");
  assert.match(result.candidates[0].label, /проверьте диапазон/);
  assert.equal(result.candidates[1].origin, "site");
});

test("OS interfaces remain a fallback without the ip command and keep small subnet masks", () => {
  const result = buildNetworkSuggestions({ ...input, interfaces: [{ device: "eth0", address: "10.8.0.6", cidr: "10.8.0.6/30" }] });
  assert.equal(result.defaultCidr, "10.8.0.4/30");
  assert.deepEqual(listHosts(result.defaultCidr), ["10.8.0.5", "10.8.0.6"]);
});

test("missing or unsuitable interfaces are guidance rather than a failed request", () => {
  const result = buildNetworkSuggestions({ ...input, targetAddress: "8.8.8.8", siteHostname: "[::1]" });
  assert.equal(result.ok, true);
  assert.equal(result.defaultCidr, "");
  assert.deepEqual(result.candidates, []);
  assert.match(result.message, /вручную/);
});

test("private scan ranges stay bounded and network and broadcast addresses are excluded", () => {
  for (const cidr of ["8.8.8.0/24", "127.0.0.0/24", "192.168.0.0/16", "10.0.0.0/23", "10.0.0.1/32", "192.168.999.0/24", "10.0.0.0/24;id"]) assert.equal(parseCidr(cidr), null, cidr);
  const hosts = listHosts("192.168.3.42/24");
  assert.equal(hosts.length, 254);
  assert.equal(hosts[0], "192.168.3.1");
  assert.equal(hosts.at(-1), "192.168.3.254");
});
