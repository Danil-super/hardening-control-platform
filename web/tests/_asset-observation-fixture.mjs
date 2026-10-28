import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

/** Replace only the authenticated remote observation in orchestration tests. */
export function installAssetObservationFixture(compiled) {
  writeFileSync(path.join(compiled.directory, "real-ssh-access.mjs"), readFileSync(path.join(compiled.directory, "ssh-access.mjs")));
  writeFileSync(path.join(compiled.directory, "ssh-access.mjs"), `
export * from "./real-ssh-access.mjs";
import {machineIdentityHash} from "./asset-binding.mjs";
export async function probeTrustedAssetIdentity() {
  return {machineIdSha256:machineIdentityHash("1234567890abcdef1234567890abcdef"),
    sshHostKeyFingerprint:"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",observedAt:new Date().toISOString()};
}
`);
}
