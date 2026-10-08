/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  serverExternalPackages: ['@sparticuz/chromium', 'playwright-core'],
  outputFileTracingIncludes: {
    '/**': ['./node_modules/@sparticuz/chromium/bin/**/*']
  }
};

export default nextConfig;
