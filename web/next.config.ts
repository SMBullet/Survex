import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",      // write static files to web/out/
  trailingSlash: false,  // /dashboard → dashboard.html (consistent with SPA fallback)
};

export default nextConfig;
