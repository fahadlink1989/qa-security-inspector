/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  serverExternalPackages: [
    '@sparticuz/chromium',
    'playwright-core',
    '@axe-core/playwright',
    'axe-core'
  ],
  outputFileTracingIncludes: {
    '/**': [
      './node_modules/@sparticuz/chromium/bin/**/*',
      './node_modules/@axe-core/playwright/**/*',
      './node_modules/axe-core/**/*'
    ]
  }
};

export default nextConfig;
