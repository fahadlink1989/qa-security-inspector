# Inspector Scanner Worker

This service executes the heavy open-source scanner engines that cannot run inside the Vercel control plane.

Supported engines:

- `zap`: OWASP ZAP passive baseline via a separately running ZAP daemon.
- `nuclei`: fixed, rate-limited safe Nuclei profile.
- `trivy`: remote Git repository dependency/misconfiguration/secret scan.
- `gitleaks`: redacted secret detection for public GitHub repositories.
- `openvas`: forwards to a dedicated Greenbone/OpenVAS adapter.

## Security model

The worker accepts only HMAC-signed requests from Inspector. Users cannot provide CLI flags or custom templates. Public-web workers reject localhost/private/reserved destinations. A dedicated internal worker may set `ALLOW_PRIVATE_TARGETS=true`.

Required environment:

```
SCANNER_WORKER_SECRET=long-random-shared-secret
PORT=8080
```

Optional:

```
ZAP_API_URL=http://zap:8080
ZAP_API_KEY=...
GREENBONE_ADAPTER_URL=https://internal-greenbone-adapter/
GREENBONE_ADAPTER_TOKEN=...
ALLOW_PRIVATE_TARGETS=false
```

Run locally:

```
docker build -t inspector-scanner-worker ./scanner-worker
docker run --rm -p 8080:8080 \
  -e SCANNER_WORKER_SECRET=change-me \
  -e ZAP_API_URL=http://host.docker.internal:8090 \
  inspector-scanner-worker
```

The public SaaS control plane should use a public-web worker. Internal-network scanning should use a separate worker/agent deployed inside the customer's network with private-target access enabled.
