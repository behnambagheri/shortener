# bea.sh Shortener

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
- **Choose allowed destinations**: approved domains only, or any HTTP/HTTPS domain.
- **Manage approved domains**: add, remove, search, or reset to the deployment defaults.
- **Manage links**: search by name or destination, see click counts, disable (returns 410), re-enable, delete, or create links even when public creation is off.
- **See totals**: links, links created in the last 7 days, clicks, and disabled links.

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

## Configuration

| Variable | Purpose |
| --- | --- |
| `PUBLIC_ORIGIN` | Origin used in generated short URLs, such as `https://s.example.com`. Defaults to the request origin. |
| `APPROVED_DOMAINS` | Default approved domains: a JSON array or comma-separated list. Defaults to `approved_domains.json`. |
| `ADMIN_TOKEN` | Admin token, at least 16 characters. |
| `ACCESS_ISSUER`, `ACCESS_AUD`, `ADMIN_EMAILS` | Optional Cloudflare Access sign-in. |
| `PORT`, `HOST`, `DATA_DIR` | Container only. Defaults: `8080`, `0.0.0.0`, `/var/lib/shortener`. |

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

For Cloudflare Access, set `admin.access.issuer`, `admin.access.aud`, and `admin.access.emails`. Other values: `approvedDomains`, `image.tag`/`image.digest`, `persistence.*`, `ingress.*`, `resources`, scheduling options.

The chart runs **one replica** with a `Recreate` strategy, because SQLite supports a single writer. Data lives on a `ReadWriteOnce` PersistentVolumeClaim (`persistence.size`, default 1Gi), which is kept when the release is uninstalled. The pod runs as non-root with a read-only root filesystem.

## API

- `GET /api/config`: approved domains, domain policy, link-creation mode, public short origin.
- `POST /api/links`: JSON `{ "original": "https://bea.sh/a/long/path", "shortened": "example" }`. Omit `shortened` to generate a random name. Returns the destination, short name, and short URL with status 201. In admin-only mode, send `Authorization: Bearer <ADMIN_TOKEN>`.
- `GET /example`: 302 redirect, with the current domain policy enforced. Disabled links return 410.
- `GET /.well-known/health`: database health, deployment commit, domain count.
- `POST /`: supports the URL-encoded HTML form.

Admin API (session cookie, bearer token, or Access JWT):

- `GET /admin/api/overview`: settings, defaults, totals, sign-in methods.
- `PUT /admin/api/settings`: any of `{ "link_creation": "public" | "admin", "domain_policy": "approved" | "any", "approved_domains": [...] | null }`. `null` restores the deployment defaults.
- `GET /admin/api/links?q=&offset=&limit=`: search and paginate links.
- `POST /admin/api/links`: create a link (works in admin-only mode).
- `PATCH /admin/api/links/<name>`: `{ "disabled": true | false }`.
- `DELETE /admin/api/links/<name>`: delete a link and free its name.

Names use 1–63 ASCII letters, numbers, hyphens, or underscores. Names are case-sensitive and immutable; collisions return 409. `admin`, `api`, `assets`, `static`, `health`, and `new` are reserved. Destinations are limited to 2,048 characters and public request bodies to 8 KiB. Redirects are not cached.

## Approved destinations

The default list is `approved_domains.json`. The initial 30 domains were discovered across connected Cloudflare zones, Worker custom domains, and ArvanCloud accounts on October 14, 2026; provenance is recorded in `docs/domain-inventory.json`. Discovery is a snapshot, not a background account sync.

Matching uses the parsed hostname and a dot boundary: `ip.bea.sh` is allowed; `evilbea.sh` and `bea.sh.evil.example` are rejected. Embedded credentials, malformed URLs, and links back to the shortener are rejected. An invalid or empty configuration fails closed.

## Local development

```sh
npm ci
npm test
npm run dev     # Workers runtime preview on http://localhost:8787
npm start       # Node container server on http://localhost:8080 (set DATA_DIR=./data)
```

`npm run dev` uses a temporary local D1 database. Its admin token is `ADMIN_TOKEN` from the environment, or `local-preview-admin-token`. Tests cover the Workers runtime with D1 (domain spoofing, concurrent alias collisions, policy changes, assets, HTML escaping, admin sign-in and management), Cloudflare Access JWT validation, and the bundled container server with SQLite persistence across restarts.

## GitHub Actions, GHCR, and Cloudflare

`.github/workflows/ci.yml` runs on pull requests, pushes to `master`, and `v*` tags:

1. **validate**: tests, Helm lint and render.
2. **container**: builds the image and runs `scripts/smoke-container.sh` (public flow, admin sign-in, admin-only mode, persistence across restarts, non-root user).
3. **publish** (not on pull requests): pushes `linux/amd64` and `linux/arm64` images to `ghcr.io/behnambagheri/shortener` tagged `latest` (default branch), `sha-<commit>`, and the version for `v*` tags, with provenance and SBOM. The packaged Helm chart is uploaded as a workflow artifact. GHCR uses the built-in `GITHUB_TOKEN`; GitHub may create the package as private at first. Make it public in the package settings if clusters pull without credentials.
4. **deploy-worker** (`master` only): applies D1 migrations, deploys the Worker with `DEPLOYMENT_SHA`, and verifies the live site. Smoke checks delete only their own randomly named fixture. Deployments are serialized.

Account: `65a8188637073a50148b1e6e59e1c1a9`. Worker/database: `bea-shortener`, declared in `wrangler.jsonc`. The `CLOUDFLARE_API_TOKEN` repository secret needs Workers Scripts and D1 write access on the account, and Workers Routes/DNS write plus Zone read on bea.sh.

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

The original `s.bea.sh` record was a proxied CNAME to `vps1.bea.sh`, TTL auto. The original Docker service and database remain intact. To return traffic to that service, detach the Worker custom domain and restore that CNAME; remove the custom-domain route from Wrangler too before the next GitHub push. Export/retain D1 first if new Cloudflare links must be preserved. For code-only rollback, redeploy an earlier known-good Worker version while retaining D1. Migration `0002_admin.sql` only adds columns, an index, and a settings table, so earlier Worker versions keep working against the migrated database.

The earlier Django implementation was removed in favor of the shared handler; it remains in Git history.
