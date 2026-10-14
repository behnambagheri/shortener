# bea.sh Shortener

A domain-restricted short-link service at **https://s.bea.sh**, running on a Cloudflare Worker with D1. Its daisyUI 5 interface shares the Space Grotesk font, grid background, colors, and light/dark themes of bea.sh and ip.bea.sh.

## Approved destinations

Edit `approved_domains.json` and push to `master` to update the list. The initial 30 domains were discovered across connected Cloudflare zones, Worker custom domains, and ArvanCloud accounts on October 14, 2026; provenance is recorded in `docs/domain-inventory.json`. Discovery is a snapshot, not a background account sync.

The API accepts HTTP and HTTPS URLs for an approved domain or any of its subdomains. Matching uses the parsed hostname and a dot boundary: `ip.bea.sh` is allowed; `evilbea.sh` and `bea.sh.evil.example` are rejected. Embedded credentials, malformed URLs, and links back to the shortener are rejected. The same policy runs on redirects, so removing a domain also disables its existing short links. An invalid or empty configuration fails closed.

An optional `APPROVED_DOMAINS` Worker variable can override the file with a JSON array or comma-separated domains. Prefer the version-controlled file; an override takes precedence until removed.

## API

- `GET /api/config`: approved domains, subdomain policy, public short origin.
- `POST /api/links`: JSON `{ "original": "https://bea.sh/a/long/path", "shortened": "example" }`. Omit `shortened` to generate a random name. Returns the destination, short name, and short URL with status 201.
- `GET /example`: 302 redirect, with the current domain policy enforced.
- `GET /.well-known/health`: database health, deployment commit, domain count.
- `POST /`: supports the original URL-encoded HTML form interface.

Names use 1–63 ASCII letters, numbers, hyphens, or underscores. Names are case-sensitive and immutable; collisions return 409. `api`, `assets`, `static`, `health`, and `new` are reserved. Destinations are limited to 2,048 characters and request bodies to 8 KiB. Redirects are not cached.

## Local preview and validation

```sh
cd cloudflare
npm ci
npm test
npm run dev
```

Open http://localhost:8787. The preview uses a temporary local D1 database. Tests exercise the actual Workers runtime and D1, including domain spoofing, concurrent alias collisions, policy changes, assets, and HTML escaping.

The optional Django implementation uses the same approved-domain file and frontend:

```sh
npm --prefix cloudflare ci
npm --prefix cloudflare run build
source /Users/behnam/.venvs/venv3.14/bin/activate
pip install -r requirements.txt
python manage.py test
python manage.py migrate
BASE_URL=http://127.0.0.1:8000 python manage.py runserver
```

Docker builds the frontend in a Node stage and starts Django after migrations. Mount `/shortener/database` for persistent SQLite storage. `APPROVED_DOMAINS` can override the file. Domain restrictions always apply; the legacy `PRIVATE` toggle no longer bypasses them. Django's uniqueness migration retains the latest row for each duplicate name, matching the old redirect behavior.

## Deployment and GitHub pushes

Account: `65a8188637073a50148b1e6e59e1c1a9` (Bagheri.linuxmail@gmail.com).
Worker/database: `bea-shortener`. Bindings and custom domain are declared in `cloudflare/wrangler.jsonc`.

Every push to `master` runs `.github/workflows/cloudflare.yml`. Pull requests run validation only. Deployment runs after tests, applies pending D1 migrations, deploys the Worker with `DEPLOYMENT_SHA`, and verifies the live UI/assets, domain restrictions, creation, redirects, alias collisions, and commit identity. Smoke checks delete only their own randomly named fixture. Deployments are serialized.

GitHub Actions uses the `CLOUDFLARE_API_TOKEN` repository secret: a dedicated account token with Workers Scripts and D1 write access scoped to the target account, and Workers Routes/DNS write plus Zone read scoped to bea.sh. No credentials are committed.

For a manual deployment, provide the same environment token:

```sh
cd cloudflare
npm ci
npm run deploy
npm run smoke
```

## Migration and rollback

The Docker SQLite database on `bea.aws.max` was read through a consistent in-memory backup without modifying its source. Only the current destination for each name was considered, using the highest source row ID to match the old app's `.last()` behavior. Migration applies the same approved-domain and short-name rules as the live Worker. Raw snapshots and destination data remain outside Git.

`cloudflare/scripts/filter-snapshot.mjs /absolute/private/directory` reads `source.sqlite3` and writes private `approved-entries.json`, `import.sql`, and a counts-only `summary.json`. Imports are idempotent for migrated rows (`created_at = 0`) and cannot overwrite newly created Cloudflare links. Run this on a fresh snapshot immediately before cutover. Do not commit snapshot files or generated SQL.

The original `s.bea.sh` record was a proxied CNAME to `vps1.bea.sh`, TTL auto. The original Docker service and database remain intact. To return traffic to that service, detach the Worker custom domain and restore that CNAME; remove the custom-domain route from Wrangler too before the next GitHub push. Export/retain D1 first if new Cloudflare links must be preserved. For code-only rollback, redeploy an earlier known-good Worker version while retaining D1; database migration rollback requires a separate data plan.
