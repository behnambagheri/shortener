# bea.sh Shortener: self-hosted URL shortener

[![CI](https://github.com/behnambagheri/shortener/actions/workflows/ci.yml/badge.svg)](https://github.com/behnambagheri/shortener/actions/workflows/ci.yml)
[![Live](https://img.shields.io/badge/live-s.bea.sh-blue)](https://s.bea.sh)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Container](https://img.shields.io/badge/ghcr.io-behnambagheri%2Fshortener-blue?logo=docker)](https://github.com/behnambagheri/shortener/pkgs/container/shortener)

A self-hosted URL shortener with custom short names, a domain allowlist, an admin dashboard and built-in phishing protection. Run it on **Cloudflare Workers + D1**, or as a **Docker** container, with **Docker Compose**, or on **Kubernetes** with Helm.

**Try it: [s.bea.sh](https://s.bea.sh)**

![bea.sh Shortener home page: create a short link with a custom name](docs/screenshot.png)

- **Custom short links**: pick a name (`s.bea.sh/my-link`) or get a random one. Names never change once created.
- **Domain allowlist**: limit short links to your own domains and their subdomains, or allow any domain.
- **Admin dashboard**: search links, see click counts, disable or delete links, and choose who can create them.
- **Abuse protection**: warning page for unknown destinations, rate limits, Cloudflare Turnstile, Google Safe Browsing, URLhaus and OpenPhish checks, abuse reports and alerts.
- **Sign-in**: admin token or Cloudflare Access for admins; GitHub or Google for visitors.
- **Runs anywhere**: one codebase for Cloudflare Workers (D1) and a Node.js container (SQLite), with a Helm chart.
- **Light and dark themes**, no tracking, no third-party scripts beyond optional Turnstile.

## Overview

A domain-restricted short-link service with an admin area. The live instance runs at **https://s.bea.sh** on a Cloudflare Worker with D1. The same code also ships as a container image (`ghcr.io/behnambagheri/shortener`) for Docker, Docker Compose, and Kubernetes (Helm), using a local SQLite database. Its daisyUI 5 interface shares the Space Grotesk font, grid background, colors, and light/dark themes of bea.sh and ip.bea.sh.

```
src/         Shared request handler, policy, admin API, browser scripts
server/      Node HTTP server and SQLite adapter for the container
migrations/  SQL migrations, applied by Wrangler (D1) and by the container at startup
templates/   Public and admin pages
charts/      Helm chart
scripts/     Build, preview, smoke tests, legacy snapshot import
```

## Admin area

Open `/admin`. Administrators can:

- **Choose who can create links**: everyone (public) or admins only. In admin-only mode the public form is disabled; the API accepts the admin bearer token or a Cloudflare Access identity. Existing links keep redirecting.
- **Choose allowed destinations**: approved domains only; any domain for signed-in visitors and approved domains for everyone else; or any HTTP/HTTPS domain.
- **Manage approved domains**: add, remove, search, or reset to the deployment defaults.
- **Manage links**: search by name or destination, filter reported, visitor-made or disabled links, see click counts, abuse reports, creator and expiry, disable (returns 410), re-enable, delete, ban a signed-in creator, or create links even when public creation is off.
- **See totals and protections**: links, links created in the last 7 days, clicks, disabled and reported links, and which abuse protections are configured.

Redirects always apply the *current* policy, so restricting destinations also stops existing links to domains that are no longer allowed. Settings saved in the admin area are stored in the database and take precedence over `APPROVED_DOMAINS` and `approved_domains.json`, which become the defaults that **Reset to deployment defaults** restores.

### Sign-in

Two methods are supported. Either one is enough; use whichever fits the deployment.

**Admin token** (any deployment: Docker, Compose, Helm, or Cloudflare). Set `ADMIN_TOKEN` to a random value of at least 16 characters:

```sh
openssl rand -hex 32
```

Enter it on `/admin`. The server sets a signed `HttpOnly`, `SameSite=Strict` session cookie scoped to `/admin` for 12 hours (`Secure` when `PUBLIC_ORIGIN` uses HTTPS). Changing the token signs everyone out. Scripts can send the token as `Authorization: Bearer <token>` instead. Tokens shorter than 16 characters disable token sign-in.

**Cloudflare Access** (the same model as ip.bea.sh). Requests carrying a valid Access JWT for an allowlisted email go straight to the dashboard:

1. In Cloudflare Zero Trust, create a self-hosted Access application covering **`s.bea.sh/admin` and all descendants**. Leave the rest of the site public.
2. Add an Allow policy for only the administrator emails. Copy the application audience (AUD) and team domain.
3. Configure `ACCESS_ISSUER=https://TEAM.cloudflareaccess.com`, `ACCESS_AUD=<audience>`, and `ADMIN_EMAILS=a@example.com,b@example.com`. All three are required.

The JWT is verified against the team's signing keys, issuer, audience, and expiry. Missing configuration or forged headers fail closed.

Admin responses are `private, no-store` and `noindex`. Cross-site writes are rejected using fetch metadata and the `Origin` header, in addition to the `SameSite=Strict` cookie.

## Abuse protection

Open shorteners attract phishing: attackers borrow the shortener's domain reputation, and the domain gets blocklisted. Links to **approved domains** are trusted and behave as before. The protections below apply to links that visitors create to **any other domain**. Administrators' links are never screened.

| Layer | What it does | Configure |
| --- | --- | --- |
| Warning page | Visitors' links outside the approved domains open a `noindex` page showing the real website and full address, with **Continue**, **Don't continue**, and **Report this link**. They never redirect directly, so the shortener is not an open redirector. | Always on |
| Rate limits | Per network per hour (IPv6 grouped by /64), and per signed-in account per day. Rejected attempts count too. | `LINKS_PER_HOUR` (10), `USER_LINKS_PER_DAY` (50); `0` disables |
| Turnstile | An invisible Cloudflare challenge before creating links outside the approved domains. | `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY` |
| Static rules | Refuses IP addresses, punycode domains, non-standard ports, other shorteners, free hosting and tunnelling services that phishing kits favor, unusually deep subdomains, and sign-in, verification or wallet-looking addresses. Approve a domain to allow it. | Always on (`src/screening.mjs`) |
| Threat feeds | Refuses destinations on the OpenPhish feed, Google Safe Browsing, and URLhaus. | Feed: `THREAT_FEED_URLS` (default OpenPhish; empty disables). `SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY` |
| New domains | Refuses domains registered less than 30 days ago, using RDAP. Unknown ages are allowed. | `NEW_DOMAIN_DAYS` (30); `0` disables |
| Re-checks | Every 3 hours, refreshes the feed and re-checks active visitor links with the feed and Safe Browsing; listed links are disabled. | Worker cron in `wrangler.jsonc`; the container runs the same job on a timer (`MAINTENANCE=off` disables) |
| Reports | One report per network per link. After enough distinct reporters, a visitor link is disabled and an alert is sent. Re-enabling a link clears its reports. | `REPORT_THRESHOLD` (3; `0` never disables), `REPORTS_PER_HOUR` (20) |
| Expiry | Anonymous visitors' links stop working after 30 days. Signed-in visitors' and admins' links do not expire. | `ANONYMOUS_LINK_DAYS` (30); `0` disables |
| Visitor sign-in | GitHub or Google sign-in ties links to an account that can be banned (which disables all of its links). GitHub accounts younger than 30 days are refused. Use the **signed_in** destination policy to let only signed-in visitors link outside the approved domains. | `SESSION_SECRET` (32+ characters), `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` and/or `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`, `MIN_ACCOUNT_DAYS` (30) |
| Alerts | Sends reports, automatic disables, and click spikes on new visitor links (100 clicks within 48 hours) to a webhook and/or Telegram. | `ALERT_WEBHOOK_URL` (JSON `{text, content}`, works with Slack and Discord), `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`, `SPIKE_CLICKS` (100) |
| Abuse contact | Shown on the home page and the warning page. | `ABUSE_EMAIL` |

Recommended public setup: destination policy **Any domain for signed-in visitors**, with Turnstile, Safe Browsing, sign-in, alerts and `ABUSE_EMAIL` configured.

Setup notes:

- **Turnstile**: create a widget for the short-link hostname in the Cloudflare dashboard (Turnstile → Add widget, mode *Invisible* or *Managed*).
- **Safe Browsing**: enable the Safe Browsing API in a Google Cloud project and create an API key restricted to it. The Lookup API is free for non-commercial use; use Google Web Risk for commercial services.
- **URLhaus**: get a free Auth-Key at [auth.abuse.ch](https://auth.abuse.ch/).
- **GitHub sign-in**: create an OAuth app with callback `https://s.bea.sh/auth/github/callback`. **Google**: create an OAuth client (web application) with redirect URI `https://s.bea.sh/auth/google/callback`.
- **Telegram**: create a bot with @BotFather, send it a message, and read the chat ID from `https://api.telegram.org/bot<token>/getUpdates`.
- Register the domain in [Google Search Console](https://search.google.com/search-console) to get an email if Google flags it, and to request a review from *Security issues*.
- **Container behind a proxy**: set `CLIENT_IP_HEADER` (for example `x-forwarded-for` or `cf-connecting-ip`), or every visitor shares the proxy's rate limit. The last `x-forwarded-for` entry is used. Only set it when a proxy always sets that header, because clients could otherwise choose their own address. The Helm chart defaults to `x-forwarded-for`.

## Configuration

| Variable | Purpose |
| --- | --- |
| `PUBLIC_ORIGIN` | Origin used in generated short URLs, such as `https://s.example.com`. Defaults to the request origin. |
| `CANONICAL_ORIGIN` | Origin the home page names as canonical. Set it on a mirror to point search engines at the primary site, such as `https://s.example.com`. Defaults to `PUBLIC_ORIGIN`. |
| `APPROVED_DOMAINS` | Default approved domains: a JSON array or comma-separated list. Defaults to `approved_domains.json`. |
| `ADMIN_TOKEN` | Admin token, at least 16 characters. |
| `ACCESS_ISSUER`, `ACCESS_AUD`, `ADMIN_EMAILS` | Optional Cloudflare Access sign-in. |
| `PORT`, `HOST`, `DATA_DIR` | Container only. Defaults: `8080`, `0.0.0.0`, `/var/lib/shortener`. |
| `CLIENT_IP_HEADER`, `MAINTENANCE` | Container only: trusted proxy header for the visitor address, and `off` to disable the scheduled job. |
| Abuse protection | See [Abuse protection](#abuse-protection). |

## Docker

```sh
docker run -d --name shortener \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 8080:8080 -v shortener-data:/var/lib/shortener \
  -e PUBLIC_ORIGIN=https://s.example.com \
  -e ADMIN_TOKEN="$(openssl rand -hex 32)" \
  ghcr.io/behnambagheri/shortener:latest
```

The image runs as UID 10001, applies database migrations at startup, and stores SQLite data in `/var/lib/shortener`. Mount a volume there to keep links and settings. Health checks use `/.well-known/health`.

## Docker Compose

Copy `.env.example` to `.env`, set `ADMIN_TOKEN` and `PUBLIC_ORIGIN`, then:

```sh
docker compose up -d
```

`docker compose build` builds the image locally instead of pulling it from GHCR.

## Kubernetes / Helm

```sh
helm upgrade --install shortener ./charts/shortener \
  --namespace shortener --create-namespace \
  --set publicOrigin=https://s.example.com \
  --set admin.token="$(openssl rand -hex 32)" \
  --set ingress.enabled=true --set ingress.className=nginx \
  --set 'ingress.hosts[0].host=s.example.com'
```

`admin.token` creates a Secret. To manage the Secret yourself:

```sh
kubectl -n shortener create secret generic shortener-admin --from-literal=token="$(openssl rand -hex 32)"
helm upgrade --install shortener ./charts/shortener -n shortener --set admin.existingSecret=shortener-admin
```

For Cloudflare Access, set `admin.access.issuer`, `admin.access.aud`, and `admin.access.emails`. Abuse protection uses `protection.env` for plain settings, and `protection.existingSecret` (or `protection.secrets`, which creates a Secret) for keys such as `SESSION_SECRET`, `TURNSTILE_SECRET_KEY`, and `SAFE_BROWSING_API_KEY`; `protection.clientIpHeader` defaults to `x-forwarded-for`. Other values: `approvedDomains`, `image.tag`/`image.digest`, `persistence.*`, `ingress.*`, `resources`, scheduling options.

The chart runs **one replica** with a `Recreate` strategy, because SQLite supports a single writer. Data lives on a `ReadWriteOnce` PersistentVolumeClaim (`persistence.size`, default 1Gi), which is kept when the release is uninstalled. The pod runs as non-root with a read-only root filesystem.

## API

- `GET /api/config`: approved domains, domain policy, whether this visitor may use any domain, link-creation mode, public short origin, Turnstile site key, sign-in providers and the signed-in visitor.
- `POST /api/links`: JSON `{ "original": "https://bea.sh/a/long/path", "shortened": "example" }`. Omit `shortened` to generate a random name. Outside the approved domains, include `"turnstile": "<token>"` when Turnstile is configured. Returns the destination, short name, short URL and `expires_at` (or null) with status 201. Too many requests return 429. In admin-only mode, send `Authorization: Bearer <ADMIN_TOKEN>`; the bearer token also skips limits and screening.
- `GET /example`: 302 redirect for admins' links and approved domains, otherwise the warning page. The current domain policy is enforced. Disabled and expired links return 410.
- `POST /api/reports`: JSON or form `{ "slug": "example", "reason": "phishing" | "malware" | "scam" | "spam" | "other" }`.
- `GET /auth/github`, `GET /auth/google`, `POST /auth/logout`: visitor sign-in.
- `GET /.well-known/health`: database health, deployment commit, domain count.
- `POST /`: supports the URL-encoded HTML form.

Admin API (session cookie, bearer token, or Access JWT):

- `GET /admin/api/overview`: settings, defaults, totals, sign-in methods.
- `PUT /admin/api/settings`: any of `{ "link_creation": "public" | "admin", "domain_policy": "approved" | "signed_in" | "any", "approved_domains": [...] | null }`. `null` restores the deployment defaults.
- `GET /admin/api/links?q=&filter=all|reported|visitors|disabled&offset=&limit=`: search and paginate links.
- `POST /admin/api/links`: create a link (works in admin-only mode).
- `PATCH /admin/api/links/<name>`: `{ "disabled": true | false }`.
- `DELETE /admin/api/links/<name>`: delete a link and free its name.
- `PATCH /admin/api/users/<provider:id>`: `{ "banned": true | false }`. Banning disables all of the account's links.

Names use 1–63 ASCII letters, numbers, hyphens, or underscores. Names are case-sensitive and immutable; collisions return 409. `admin`, `api`, `assets`, `auth`, `static`, `health`, and `new` are reserved. Destinations are limited to 2,048 characters and public request bodies to 8 KiB. Redirects are not cached.

## Approved destinations

The default list is `approved_domains.json`. The initial 30 domains were discovered across connected Cloudflare zones, Worker custom domains, and ArvanCloud accounts on October 14, 2026; provenance is recorded in `docs/domain-inventory.json`. Discovery is a snapshot, not a background account sync.

Matching uses the parsed hostname and a dot boundary: `ip.bea.sh` is allowed; `evilbea.sh` and `bea.sh.evil.example` are rejected. Basic-auth credentials such as `http://user:pass@host/` are allowed, and the policy checks the real hostname, so `https://bea.sh@evil.example` counts as `evil.example`. Malformed URLs and links back to the shortener are rejected. An invalid or empty configuration fails closed.

## Local development

```sh
npm ci
npm test
npm run dev     # Workers runtime preview on http://localhost:8787
npm start       # Node container server on http://localhost:8080 (set DATA_DIR=./data)
```

`npm run dev` uses a temporary local D1 database. Its admin token is `ADMIN_TOKEN` from the environment, or `local-preview-admin-token`. Tests cover the Workers runtime with D1 (domain spoofing, concurrent alias collisions, policy changes, assets, HTML escaping, admin sign-in and management, and abuse protection with mocked outbound services: warning page, Turnstile, screening, rate limits, reports, scheduled re-checks, alerts, visitor sign-in and bans), Cloudflare Access JWT validation, and the bundled container server with SQLite persistence and proxy-aware rate limits.

## GitHub Actions, GHCR, and Cloudflare

`.github/workflows/ci.yml` runs on pull requests, pushes to `master`, and `v*` tags:

1. **validate**: tests, Helm lint and render.
2. **container**: builds the image and runs `scripts/smoke-container.sh` (public flow, admin sign-in, admin-only mode, persistence across restarts, non-root user).
3. **publish** (not on pull requests): pushes `linux/amd64` and `linux/arm64` images to `ghcr.io/behnambagheri/shortener` tagged `latest` (default branch), `sha-<commit>`, and the version for `v*` tags, with provenance and SBOM. The packaged Helm chart is uploaded as a workflow artifact. GHCR uses the built-in `GITHUB_TOKEN`; GitHub may create the package as private at first. Make it public in the package settings if clusters pull without credentials.
4. **deploy-worker** (`master` only): applies D1 migrations, deploys the Worker with `DEPLOYMENT_SHA`, and verifies the live site. Smoke checks delete only their own randomly named fixture. Deployments are serialized.

Account: `65a8188637073a50148b1e6e59e1c1a9`. Worker/database: `bea-shortener`, declared in `wrangler.jsonc`. The `CLOUDFLARE_API_TOKEN` repository secret needs Workers Scripts and D1 write access on the account, and Workers Routes/DNS write plus Zone read on bea.sh.

The Worker has a cron trigger (`17 */3 * * *`) for the abuse-protection job. Abuse-protection keys are Worker secrets too (`npx wrangler secret put TURNSTILE_SECRET_KEY`, `SAFE_BROWSING_API_KEY`, `SESSION_SECRET`, `GITHUB_CLIENT_SECRET`, ...); plain settings such as `TURNSTILE_SITE_KEY` or `ABUSE_EMAIL` can be secrets or `vars`.

Admin sign-in on the Worker uses Worker secrets, which persist across deployments:

```sh
npx wrangler secret put ADMIN_TOKEN
# Or, for Cloudflare Access:
npx wrangler secret put ACCESS_ISSUER
npx wrangler secret put ACCESS_AUD
npx wrangler secret put ADMIN_EMAILS
```

For a manual Worker deployment with the same token in the environment:

```sh
npm ci
npm run deploy
npm run smoke
```

## Migration and rollback

The Docker SQLite database on `bea.aws.max` was read through a consistent in-memory backup without modifying its source. Only the current destination for each name was considered, using the highest source row ID to match the old app's `.last()` behavior. Migration applies the same approved-domain and short-name rules as the live Worker. Raw snapshots and destination data remain outside Git.

`scripts/filter-snapshot.mjs /absolute/private/directory` reads `source.sqlite3` and writes private `approved-entries.json`, `import.sql`, and a counts-only `summary.json`. Imports are idempotent for migrated rows (`created_at = 0`) and cannot overwrite newly created links. Run `import.sql` against D1 with Wrangler, or against the container database with `sqlite3 /var/lib/shortener/shortener.sqlite3 < import.sql` while the service is stopped. Do not commit snapshot files or generated SQL.

The original `s.bea.sh` record was a proxied CNAME to `vps1.bea.sh`, TTL auto. The original Docker service and database remain intact. To return traffic to that service, detach the Worker custom domain and restore that CNAME; remove the custom-domain route from Wrangler too before the next GitHub push. Export/retain D1 first if new Cloudflare links must be preserved. For code-only rollback, redeploy an earlier known-good Worker version while retaining D1. Migrations `0002_admin.sql` and `0003_abuse.sql` only add columns, indexes and tables, so earlier Worker versions keep working against the migrated database. Links created before `0003` count as visitors' links, so those outside the approved domains show the warning page.

The earlier Django implementation was removed in favor of the shared handler; it remains in Git history. The project started from [AliRn76/shortener](https://github.com/AliRn76/shortener) and has since been rewritten.

## License

[MIT](LICENSE)
