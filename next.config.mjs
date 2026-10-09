/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  async rewrites() {
    return {beforeFiles:process.env.INSPECTOR_BACKEND==='1'?[]:[{source:'/api/:path*',destination:'https://inspector-backend-production-f6e0.up.railway.app/api/:path*'}]};
  },
  // Browser libraries serialize functions for injection. Keep them external so
  // bundler minification cannot introduce out-of-scope browser identifiers.
  serverExternalPackages: [
    '@sparticuz/chromium',
    '@axe-core/playwright',
    'axe-core',
    'playwright-core'
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

