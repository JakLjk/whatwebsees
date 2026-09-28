#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
worker_directory=$(CDPATH= cd -- "$script_directory/.." && pwd)
asset_directory="$worker_directory/speed-assets/speed-test/download"

umask 077
mkdir -p "$asset_directory"

generate_asset() {
    filename=$1
    mebibytes=$2
    dd \
        if=/dev/urandom \
        of="$asset_directory/$filename" \
        bs=1048576 \
        count="$mebibytes" \
        status=none
}

generate_asset "payload-1m.bin" 1
generate_asset "payload-4m.bin" 4
generate_asset "payload-16m.bin" 16
generate_asset "payload-24m.bin" 24

printf '%s\n' "Generated incompressible speed-test assets in $asset_directory"
