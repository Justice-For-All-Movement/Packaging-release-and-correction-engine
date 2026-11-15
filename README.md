# Packaging Release and Correction Engine

Reusable country-neutral engine. Initial capabilities and limits are documented in [architecture](docs/ARCHITECTURE.md); the canonical work plan is [registry/prs.json](registry/prs.json).

```sh
npm ci
npm run check
```

All research and jurisdiction configuration belong in downstream deployments. Implementation, local tests, CI, merge and live acceptance are separate.

## Service layer

The engine service (`src/engine/`, package export `./engine`) builds packages, runs leak prevention, and manages
private review, exact-version approval, release, receipts, distribution history, corrections and withdrawals on
PostgreSQL (schema `e12_release`). Full surface and honest status: [docs/ENGINE_API.md](docs/ENGINE_API.md).

```sh
# run (standalone)
DATABASE_URL=postgresql://… IDENTITY_PUBLIC_KEYS='{"kid":"-----BEGIN PUBLIC KEY-----…"}' \
OBJECT_STORE_PATH=./data/objects RELEASE_JURISDICTION_PACKS_DIR=./examples/jurisdiction-packs \
RELEASE_DESTINATION_ROOTS='{"portal":"/srv/review-portal"}' npm run serve

# test (real PostgreSQL, real pandoc/LibreOffice/exiftool/poppler/ImageMagick/ffmpeg)
TEST_DATABASE_URL=postgresql://pam:pam@127.0.0.1:5432/postgres npm run check
```

```ts
import { createEngine, migrate, routes } from '@accountability/packaging-release/engine';
await migrate(sql);
const engine = createEngine({ sql, objects, ports: { useDecision, useRegister, authorization, evidence, protectedTerms }, config });
```

The only jurisdiction pack shipped is the fictional "Example Republic" under `examples/`; real packs are deployment data.
