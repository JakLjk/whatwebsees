# Web Privacy Inspector

A privacy-focused web application that shows visitors what information a normal website can technically observe about their browser and connection.

The current implementation is intentionally limited to an infrastructure skeleton. It does not inspect or persist visitor information.

## Current architecture

Local diagnostic requests made on the VM follow this path:

```text
127.0.0.1:8080 -> Nginx -> Gunicorn -> Django
```

Production requests follow this path:

```text
Cloudflare -> cloudflared -> Nginx -> Gunicorn -> Django
```

Cloudflared runs a remotely-managed Cloudflare Tunnel and communicates with Nginx over the `edge` network. The public hostname must use `http://nginx:80` as its service in the Cloudflare dashboard. Nginx communicates with Django/Gunicorn over the internal `backend` network.

No public inbound ports are exposed directly from the VM. Nginx remains published only at `127.0.0.1:8080` for local diagnostics, and Gunicorn has no host port. SQLite data is stored in `./data` on the host and mounted at `/data` in the Django container.

## Trusted proxy headers

Cloudflare supplies the visitor address in `CF-Connecting-IP`. Nginx normalizes that header into `X-Real-IP`, falling back to its direct peer address for local diagnostic requests. Application code must use this normalized value for visitor identity and must not trust arbitrary values in `X-Forwarded-For`.

Nginx also preserves Cloudflare's incoming `X-Forwarded-Proto` value, falling back to its own request scheme when the header is absent. This lets Django recognize the original HTTPS request even though cloudflared connects to Nginx over HTTP.

Client IP addresses are not logged or stored. Nginx and Gunicorn access logging remain disabled, and the application does not persist request or visitor data.

## Privacy principles

- Do not persist visitor IP addresses unless technically necessary.
- Do not build persistent browser fingerprints.
- Avoid unnecessary tracking.
- Keep secrets outside Git.
- Review GDPR/ePrivacy implications before adding analytics or advertising.

## Status

Minimal local Django/Gunicorn/Nginx stack.

## Local operation

Create a local environment file, replace the Django placeholder secret with a unique value, and set the Cloudflare Tunnel token:

```sh
cp .env.example .env
```

The `.env` file is ignored by Git and must not be committed.
The tunnel token belongs only in `.env`; do not place it in Compose files, documentation, or Git.

Build and start the services:

```sh
sudo docker compose config
sudo docker compose build
sudo docker compose up -d
```

Check service state and the complete request path:

```sh
sudo docker compose ps
curl --fail http://127.0.0.1:8080/health
```

Run the Django system check and automated tests:

```sh
sudo docker compose exec web python manage.py check
sudo docker compose exec web python manage.py test
```

Stop the services:

```sh
sudo docker compose down
```
