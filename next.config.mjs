/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  async rewrites() {
    return {beforeFiles:process.env.INSPECTOR_BACKEND==='1'?[]:[{source:'/api/:path*',destination:'https://inspector-backend-production-f6e0.up.railway.app/api/:path*'}]};
  },
  // Keep only the native Chromium payload external. Playwright and axe stay
  // bundled so their JS runtime can be traced correctly by Next.js 16.
  serverExternalPackages: [
    '@sparticuz/chromium'
  ],
  outputFileTracingIncludes: {
    '/**': [
      './node_modules/@sparticuz/chromium/bin/**/*',
      './node_modules/playwright-core/browsers.json',
      './node_modules/playwright-core/package.json',
      './node_modules/playwright-core/lib/**/*',
      './node_modules/@axe-core/playwright/**/*',
      './node_modules/axe-core/**/*'
    ]
  }
};

export default nextConfig;

