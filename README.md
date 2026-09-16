# Web Privacy Inspector

A privacy-focused web application that shows visitors what information a normal website can technically observe about their browser and connection.

The current implementation is intentionally limited to an infrastructure skeleton. It does not inspect or persist visitor information.

## Current architecture

Requests made on the VM follow this path:

```text
127.0.0.1:8080 -> Nginx -> Gunicorn -> Django
```

Only Nginx is published to the host, and it is bound to the loopback interface. Gunicorn is available only on the internal Docker network. SQLite data is stored in `./data` on the host and mounted at `/data` in the Django container.

The eventual planned stack is:

- Debian 13 VM on Proxmox
- Docker Engine + Docker Compose
- Python / Django
- Gunicorn
- Nginx
- Cloudflare Tunnel
- SQLite for the initial MVP

Cloudflare Tunnel is not configured yet. No inbound public web ports are exposed directly on the VM.

## Privacy principles

- Do not persist visitor IP addresses unless technically necessary.
- Do not build persistent browser fingerprints.
- Avoid unnecessary tracking.
- Keep secrets outside Git.
- Review GDPR/ePrivacy implications before adding analytics or advertising.

## Status

Minimal local Django/Gunicorn/Nginx stack.

## Local operation

Create a local environment file and replace the placeholder secret with a unique value:

```sh
cp .env.example .env
```

The `.env` file is ignored by Git and must not be committed.

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
