import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";
const compiled = compileServerModules(["security-events"]);
const { describeSecurityEvent, groupSecurityEvents } = await import(compiled.url("security-events"));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));

test("UFW journal becomes readable endpoints without claiming a compromise or inventing a year", () => {
  const message = "/var/log/syslog:Oct  9 16:19:11 astra17 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.95.1 DST=172.16.95.128 PROTO=TCP SPT=56920 DPT=8888 SYN";
  const event = describeSecurityEvent({ source: "ufw_denied", message });
  assert.equal(event.title, "Соединение заблокировано");
  assert.equal(event.time, "Oct  9 16:19:11");
  assert.deepEqual(Object.fromEntries(event.fields.map(f => [f.label, f.value])), { Откуда: "172.16.95.1", Куда: "172.16.95.128", "Порт назначения": "8888", Протокол: "TCP", Интерфейс: "eth0" });
  assert.equal(event.raw, message);
  assert.match(groupSecurityEvents([{ source: "ufw_denied", message }])[0].description, /не подтверждают/);
  assert.equal(describeSecurityEvent({ source: "ufw_denied", message: "[UFW DENY] SRC=2001:db8::1 DST=2001:db8::2 PROTO=UDP DPT=53" }).fields[0].value, "2001:db8::1");
});

test("authentication and Suricata expose recorded evidence, preserve malformed and unknown records", () => {
  const auth = describeSecurityEvent({ source: "auth_failed", message: "Failed password for invalid user admin from 192.0.2.4 port 123 ssh2" });
  assert.equal(auth.title, "Вход с неизвестной учётной записью");
  assert.equal(auth.fields[0].value, "admin"); assert.equal(auth.fields[1].value, "192.0.2.4");
  const eve = describeSecurityEvent({ source: "suricata_eve", message: JSON.stringify({ timestamp: "2026-10-09T12:00:00Z", src_ip: "192.0.2.1", dest_port: 443, alert: { signature: "Test alert", action: "blocked" } }) });
  assert.equal(eve.title, "Test alert"); assert.equal(eve.time, "2026-10-09T12:00:00Z");
  assert.equal(eve.fields.at(-1).value, "Заблокировано");
  const raw = '<script>alert("x")</script>';
  const groups = groupSecurityEvents([{ source: "unknown-source", message: raw }, { source: "suricata_eve", message: '{"truncated"' }, { source: "unknown-source", message: raw }]);
  assert.equal(groups.length, 2); assert.equal(groups[0].events.length, 2);
  assert.equal(groups[0].events[0].raw, raw); assert.equal(groups[1].events[0].fields.length, 0);
  assert.deepEqual(groupSecurityEvents([]), []);
  assert.doesNotThrow(() => groupSecurityEvents([null, { source: 42, message: {} }]));
});
