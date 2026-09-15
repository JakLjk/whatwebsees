# Web Privacy Inspector

A privacy-focused web application that shows visitors what information a normal website can technically observe about their browser and connection.

## Planned stack

- Debian 13 VM on Proxmox
- Docker Engine + Docker Compose
- Python / Django
- Gunicorn
- Nginx
- Cloudflare Tunnel
- SQLite for the initial MVP

## Architecture

Cloudflare
    -> Cloudflare Tunnel
    -> Nginx
    -> Gunicorn
    -> Django

No inbound public web ports are exposed directly on the VM.

## Privacy principles

- Do not persist visitor IP addresses unless technically necessary.
- Do not build persistent browser fingerprints.
- Avoid unnecessary tracking.
- Keep secrets outside Git.
- Review GDPR/ePrivacy implications before adding analytics or advertising.

## Status

Infrastructure setup in progress.
