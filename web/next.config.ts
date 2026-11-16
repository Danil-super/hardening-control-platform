import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Keep build workers within the controller's memory budget on many-core hosts.
  experimental: { cpus: 2 },
};

export default nextConfig;
