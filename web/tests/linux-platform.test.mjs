import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["linux-platform"]);
const { resolveLinuxPlatform } = await import(compiled.url("linux-platform"));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));

test("exact distributions retain independent advisory ownership", () => {
  for (const [id, manager, family] of [["ubuntu", "dpkg", "ubuntu"], ["debian", "dpkg", "debian"],
    ["rhel", "rpm", "redhat"], ["rocky", "rpm", "rocky"], ["almalinux", "rpm", "alma"],
    ["alpine", "apk", "alpine"], ["sles", "rpm", "sles"],
    ["opensuse-leap", "rpm", "opensuse-leap"], ["opensuse-tumbleweed", "rpm", "opensuse-tumbleweed"]]) {
    const result = resolveLinuxPlatform({ ID: id, VERSION_ID: "9", ID_LIKE: "linux" });
    assert.equal(result.id, id); assert.equal(result.packageManager, manager);
    assert.equal(result.trivyFamily, family); assert.equal(result.packageCveProvider, "trivy");
    assert.equal(result.collectionFamilyInferred, false);
  }
});

test("derivatives and CentOS Stream never inherit a parent's vulnerability source", () => {
  for (const os of [{ ID: "custom-linux", ID_LIKE: "rhel fedora" }, { ID: "linuxmint", ID_LIKE: "ubuntu debian" },
    { ID: "redos", ID_LIKE: "rhel" }, { ID: "altlinux", ID_LIKE: "rhel" },
    { ID: "sled", ID_LIKE: "suse" }, { ID: "centos", NAME: "CentOS Stream" }]) {
    const result = resolveLinuxPlatform(os);
    assert.ok(["dpkg", "rpm"].includes(result.packageManager));
    assert.equal(result.packageCveProvider, "vendor-required"); assert.equal(result.trivyFamily, null);
  }
});

test("Astra identity remains distinct even when os-release says Debian", () => {
  for (const os of [{ ID: "astra", ID_LIKE: "debian" }, { ID: "debian" }]) {
    const result = resolveLinuxPlatform(os, "1.7.6");
    assert.equal(result.packageManager, "dpkg"); assert.equal(result.packageCveProvider, "astra-oval");
    assert.equal(result.trivyFamily, null);
  }
});

test("unknown identity and missing release never manufacture verified coverage", () => {
  for (const os of [{}, { ID: "../ubuntu" }, { ID: "arch" }, { ID: "nixos" }]) {
    const result = resolveLinuxPlatform(os);
    assert.equal(result.trivyFamily, null); assert.equal(result.packageManager, null);
    assert.ok(result.notes.some((note) => note.includes("Версия ОС")));
  }
});

test("collection-only platform registrations do not claim an unvalidated CVE adapter", () => {
  for (const id of ["centos-stream", "opensuse", "slem", "photon", "cbl-mariner", "azurelinux", "chainguard"]) {
    const result = resolveLinuxPlatform({ ID: id, VERSION_ID: "1" });
    assert.equal(result.packageManager, id === "chainguard" ? "apk" : "rpm");
    assert.equal(result.packageCveProvider, "vendor-required"); assert.equal(result.trivyFamily, null);
  }
});
