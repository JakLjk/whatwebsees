#!/usr/bin/env bash
set -Eeuo pipefail

umask 022

PROJECT_DIR="/srv/web-privacy"
GEOIP_DIR="${PROJECT_DIR}/data/geoip"
CURRENT_DB="${GEOIP_DIR}/dbip-city-lite.mmdb"
PREVIOUS_DB="${GEOIP_DIR}/dbip-city-lite.previous.mmdb"

RELEASE="$(date +%Y-%m)"
DOWNLOAD_URL="https://download.db-ip.com/free/dbip-city-lite-${RELEASE}.mmdb.gz"

mkdir -p "${GEOIP_DIR}"

# Prevent two updates from running at the same time.
exec 9>"${GEOIP_DIR}/.update.lock"
if ! flock -n 9; then
    echo "Another GeoIP update is already running."
    exit 0
fi

TMP_GZ="$(mktemp -p "${GEOIP_DIR}" ".dbip-${RELEASE}.XXXXXX.mmdb.gz")"
TMP_MMDB="${TMP_GZ%.gz}"

cleanup() {
    if [[ -n "${TMP_GZ:-}" ]]; then
        rm -f -- "${TMP_GZ}"
    fi

    if [[ -n "${TMP_MMDB:-}" ]]; then
        rm -f -- "${TMP_MMDB}"
    fi
}
trap cleanup EXIT

echo "DB-IP release: ${RELEASE}"
echo "Downloading: ${DOWNLOAD_URL}"

curl \
    --fail \
    --location \
    --retry 3 \
    --retry-delay 10 \
    --connect-timeout 20 \
    --max-time 900 \
    --output "${TMP_GZ}" \
    "${DOWNLOAD_URL}"

echo "Checking gzip integrity..."
gzip -t "${TMP_GZ}"

echo "Extracting candidate database..."
gzip -dc "${TMP_GZ}" > "${TMP_MMDB}"
chmod 0644 "${TMP_MMDB}"

cd "${PROJECT_DIR}"

CONTAINER_TMP="/data/geoip/$(basename "${TMP_MMDB}")"

echo "Validating MMDB structure with application Python..."
docker compose exec -T web python - "${CONTAINER_TMP}" <<'PY'
import sys

import maxminddb

path = sys.argv[1]

with maxminddb.open_database(path) as reader:
    metadata = reader.metadata()

    if metadata.node_count <= 0:
        raise SystemExit("MMDB validation failed: empty database")

    # Sanity-check that the database can actually perform a lookup.
    result = reader.get("8.8.8.8")

    if not isinstance(result, dict):
        raise SystemExit("MMDB validation failed: test lookup returned no record")

    print("MMDB validation: OK")
    print("Nodes:", metadata.node_count)
    print("IP version:", metadata.ip_version)
PY

NEW_SHA="$(sha256sum "${TMP_MMDB}" | awk '{print $1}')"
echo "Candidate SHA256: ${NEW_SHA}"

if [[ -f "${CURRENT_DB}" ]]; then
    CURRENT_SHA="$(sha256sum "${CURRENT_DB}" | awk '{print $1}')"
    echo "Current SHA256:   ${CURRENT_SHA}"

    if [[ "${NEW_SHA}" == "${CURRENT_SHA}" ]]; then
        echo "Database is already current. Nothing to replace."
        exit 0
    fi
fi

echo "Creating rollback copy..."
if [[ -f "${CURRENT_DB}" ]]; then
    PREVIOUS_TMP="${PREVIOUS_DB}.tmp"
    rm -f "${PREVIOUS_TMP}"

    cp --reflink=auto --preserve=mode,timestamps \
        "${CURRENT_DB}" \
        "${PREVIOUS_TMP}"

    mv -f "${PREVIOUS_TMP}" "${PREVIOUS_DB}"
fi

echo "Installing new database atomically..."
mv -f "${TMP_MMDB}" "${CURRENT_DB}"
TMP_MMDB=""

chmod 0644 "${CURRENT_DB}"

echo "Restarting Django web container..."
docker compose restart web

echo "Waiting for application health check..."

HEALTHY=0

for attempt in $(seq 1 30); do
    if curl \
        --fail \
        --silent \
        --show-error \
        --max-time 3 \
        http://127.0.0.1:8080/health \
        >/dev/null 2>&1
    then
        HEALTHY=1
        break
    fi

    sleep 1
done

if [[ "${HEALTHY}" != "1" ]]; then
    echo "ERROR: application did not become healthy."

    if [[ -f "${PREVIOUS_DB}" ]]; then
        echo "Rolling back previous GeoIP database..."
        cp -f "${PREVIOUS_DB}" "${CURRENT_DB}"
        chmod 0644 "${CURRENT_DB}"
        docker compose restart web
    fi

    exit 1
fi

echo "GeoIP update completed successfully."
