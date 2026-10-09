# Website performance

Targets → Speed opens Google PageSpeed Insights mobile and desktop measurements. The job runs on the backend consumer, is workspace scoped, and saves up to 40 measurements per target group. Scans and target history include the results. Performance results do not change security scores or generate security findings.

Metrics: Lighthouse performance score, FCP, LCP, Speed Index, TBT, CLS and TTI when supplied. Failed audits include provider descriptions, resource samples and estimated savings. Page and origin field data are separate; absent CrUX data remains unavailable. Google is migrating field data to separate CrUX APIs; no field values are invented.

Settings → Google PageSpeed Insights accepts a workspace API key, encrypts it with workspace-bound authenticated encryption, and never returns it to the browser. PAGESPEED_API_KEY is an optional backend environment fallback. Enable PageSpeed Insights API and restrict the key to this API. Unauthenticated access is attempted without a key but may receive quota errors. Provider failures are persisted without fabricated scores.

QA uses a temporary workspace and an authorized test of Inspector itself. Fixture parsing tests are only in tests/performance.test.mjs. No fixture or dummy measurement is served to customers.
