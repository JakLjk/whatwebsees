# WhatWebSees speed-test Worker

This module serves the non-indexable speed-test endpoints at
`whatwebsees.com/speed-test/*` from Cloudflare's edge. Download payloads use
Workers Static Assets so application-origin upload capacity cannot cap a
browser's download measurement. Worker code handles only HTTP latency and
bounded uploads.

## Architecture and endpoints

- `GET /speed-test/download/payload-1m.bin`, `payload-4m.bin`,
  `payload-16m.bin` and `payload-24m.bin` are Workers Static Assets. Matching
  requests are served asset-first without invoking Worker code.
- `GET /speed-test/ping/` invokes Worker code and returns a minimal response for
  browser-measured HTTP latency.
- `POST /speed-test/upload/` invokes Worker code, accepts
  `application/octet-stream`, counts at most 16 MiB as a stream, and never
  stores or forwards the body.

The static files carry
`X-WWS-Speedtest-Backend: cloudflare-static-asset`; dynamic responses carry
`X-WWS-Speedtest-Backend: cloudflare-worker`. Both response types are
non-cacheable and non-indexable. The browser refuses to report a measurement
when the expected marker is absent or different.

`wrangler.toml` points `assets.directory` at `./speed-assets` and deliberately
does not enable `run_worker_first`. Cloudflare therefore serves a matching
payload directly as a Static Asset. Requests with no matching file, including
the ping and upload endpoints, invoke `src/index.js`.

## Generate the download assets

The generated binaries are ignored by Git and Docker. Generate them locally
before tests, local development or deployment:

```sh
npm run assets:generate
wc -c speed-assets/speed-test/download/*.bin
```

The expected byte counts are:

| File | Exact size |
| --- | ---: |
| `payload-1m.bin` | 1,048,576 bytes |
| `payload-4m.bin` | 4,194,304 bytes |
| `payload-16m.bin` | 16,777,216 bytes |
| `payload-24m.bin` | 25,165,824 bytes |

The generator reads `/dev/urandom`, so the payloads are not trivially
compressible. The largest file is 24 MiB, below Cloudflare's current 25 MiB
individual Static Asset limit. Do not commit these files.

## Local validation

Node 20 or newer is required. No Cloudflare account is needed for unit tests.

```sh
npm install
npm run assets:generate
npm run check
npm test
npx wrangler deploy --dry-run --outdir /tmp/whatwebsees-worker-dryrun
```

`npm run dev` uses the generated local asset directory. Local Wrangler state,
authentication files and generated binaries are ignored by Git.

## Free-plan behavior

Cloudflare currently documents requests served as Workers Static Assets as
free and unlimited, with no additional charge for storing those assets. The
download payloads match files and therefore do not need Worker-script
invocations. The dynamic ping and upload endpoints do invoke the Worker and are
subject to the Workers Free limits, currently including a 100,000-request daily
quota.

If the dynamic quota is exhausted, an edge error or an origin fallback without
the required backend marker causes the browser test to fail with “Speed-test
edge service is unavailable.” It cannot silently turn into an origin-backed
measurement. Configure the production route in fail-closed mode where that
account setting is available.

This speed-test design does not require Workers Paid or a usage-based storage
product. That statement is specific to this design; it is not a claim that
every Cloudflare feature or account configuration is always free.

Cloudflare documentation:

- [Static Assets routing](https://developers.cloudflare.com/workers/static-assets/)
- [Static Assets billing and limitations](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/)
- [Workers limits](https://developers.cloudflare.com/workers/platform/limits/)
- [Static Asset headers](https://developers.cloudflare.com/workers/static-assets/headers/)

## Manual deployment

These are administrator instructions only. This repository change does not run
them against production.

1. Install dependencies and generate the four assets.
2. Confirm their exact sizes and run all tests plus Wrangler's dry run.
3. Review the `whatwebsees.com/speed-test/*` route and select fail-closed route
   behavior in Cloudflare rather than origin bypass.
4. Deploy from this directory with `npm run deploy` using the administrator's
   normal secure Cloudflare authentication process.
5. Verify both backend markers before exposing the UI.

The configuration contains no account ID, API token, password or secret.

### Post-deployment verification

Inspect headers and confirm ping/upload report `cloudflare-worker`, downloads
report `cloudflare-static-asset`, and all responses are non-cacheable and
non-indexable. Count the downloaded body itself rather than depending on a
`Content-Length` header:

```sh
curl --fail --silent --show-error --dump-header - --output /dev/null \
  https://whatwebsees.com/speed-test/ping/
curl --fail --silent --show-error \
  --dump-header /tmp/whatwebsees-speedtest-download.headers \
  'https://whatwebsees.com/speed-test/download/payload-1m.bin?nonce=verify' \
  | wc -c
dd if=/dev/urandom bs=1048576 count=1 status=none | \
  curl --fail --silent --show-error --dump-header - --output /dev/null \
  --header 'Content-Type: application/octet-stream' \
  --data-binary @- \
  https://whatwebsees.com/speed-test/upload/
```

The download count must be `1048576`. On the origin host, separately verify the
legacy bypass path stays fail-closed:

```sh
curl --include --header 'Host: whatwebsees.com' \
  'http://127.0.0.1:8080/speed-test/download/'
```

That origin response must be a small `503` with
`X-WWS-Speedtest-Backend: django-fallback`, never binary test data.

## Abuse controls

nginx cannot rate-limit these requests because the Cloudflare route executes
before the Tunnel and origin. A full browser run can make 5 dynamic latency
requests, up to 11 static download requests and up to 7 dynamic upload
requests. If the account provides suitable Cloudflare-side rate-limiting
controls, scope them to the exact paths, allow one adaptive run's short burst,
and apply stricter sustained per-source limits. Monitor Worker invocations and
bandwidth, then tune limits for shared-address users and actual traffic.
