import assert from "node:assert/strict";
import {stat, readFile} from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {fileURLToPath} from "node:url";

import {
    BACKEND,
    MAX_UPLOAD_BYTES,
    handleRequest,
} from "../src/index.js";

const ORIGIN = "https://whatwebsees.com";
const MIB = 1024 * 1024;
const MAX_STATIC_ASSET_BYTES = 25 * MIB;
const WORKER_DIRECTORY = fileURLToPath(new URL("../", import.meta.url));
const REPOSITORY_DIRECTORY = fileURLToPath(new URL("../../../", import.meta.url));
const STATIC_ASSETS = Object.freeze({
    "payload-1m.bin": MIB,
    "payload-4m.bin": 4 * MIB,
    "payload-16m.bin": 16 * MIB,
    "payload-24m.bin": 24 * MIB,
});

function boundedStream(length) {
    let remaining = length;
    return new ReadableStream({
        pull(controller) {
            if (remaining === 0) {
                controller.close();
                return;
            }
            const chunkSize = Math.min(64 * 1024, remaining);
            remaining -= chunkSize;
            controller.enqueue(new Uint8Array(chunkSize));
        },
    });
}

function assertProtected(response) {
    assert.equal(response.headers.get("X-WWS-Speedtest-Backend"), BACKEND);
    assert.equal(response.headers.get("X-Robots-Tag"), "noindex, nofollow");
    assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
    assert.match(response.headers.get("Cache-Control"), /no-store/);
    assert.match(response.headers.get("Cache-Control"), /no-cache/);
    assert.match(response.headers.get("Cache-Control"), /no-transform/);
}

test("configuration uses asset-first Workers Static Assets with no storage binding", async () => {
    const [configuration, source] = await Promise.all([
        readFile(path.join(WORKER_DIRECTORY, "wrangler.toml"), "utf8"),
        readFile(path.join(WORKER_DIRECTORY, "src/index.js"), "utf8"),
    ]);

    assert.match(configuration, /\[assets\]\s+directory = "\.\/speed-assets"/);
    assert.doesNotMatch(configuration, /run_worker_first/);
    assert.doesNotMatch(configuration, /r2_buckets|SPEED_DATA|bucket_name/i);
    assert.doesNotMatch(source, /SPEED_DATA|payload\.bin|ranged? read/i);
    assert.doesNotMatch(source, /\/speed-test\/download\//);
});

test("generated static assets are ignored, exact-sized, and below 25 MiB", async () => {
    const ignoreRule = "cloudflare/speed-test-worker/speed-assets/speed-test/download/";
    const [gitIgnore, dockerIgnore] = await Promise.all([
        readFile(path.join(REPOSITORY_DIRECTORY, ".gitignore"), "utf8"),
        readFile(path.join(REPOSITORY_DIRECTORY, ".dockerignore"), "utf8"),
    ]);
    assert.ok(gitIgnore.split(/\r?\n/).includes(ignoreRule));
    assert.ok(dockerIgnore.split(/\r?\n/).includes(ignoreRule));

    for (const [filename, expectedBytes] of Object.entries(STATIC_ASSETS)) {
        assert.ok(expectedBytes <= MAX_STATIC_ASSET_BYTES, filename);
        const absolutePath = path.join(
            WORKER_DIRECTORY,
            "speed-assets/speed-test/download",
            filename,
        );
        assert.equal((await stat(absolutePath)).size, expectedBytes, filename);
    }
});

test("static download header rules identify and protect binary assets", async () => {
    const headers = await readFile(
        path.join(WORKER_DIRECTORY, "speed-assets/_headers"),
        "utf8",
    );
    for (const expected of [
        "/speed-test/download/*.bin",
        "Content-Type: application/octet-stream",
        "Content-Encoding: identity",
        "Cache-Control: no-store, no-cache, no-transform",
        "X-Robots-Tag: noindex, nofollow",
        "X-WWS-Speedtest-Backend: cloudflare-static-asset",
        "Cross-Origin-Resource-Policy: same-origin",
        "X-Content-Type-Options: nosniff",
    ]) {
        assert.ok(headers.includes(expected), expected);
    }
});

test("unknown paths and wrong dynamic endpoint methods fail closed", async () => {
    const unknown = await handleRequest(
        new Request(`${ORIGIN}/speed-test/download/not-an-asset.bin`),
    );
    assert.equal(unknown.status, 404);
    assertProtected(unknown);

    for (const [pathName, method, allow] of [
        ["ping/", "POST", "GET"],
        ["upload/", "GET", "POST"],
    ]) {
        const response = await handleRequest(
            new Request(`${ORIGIN}/speed-test/${pathName}`, {method}),
        );
        assert.equal(response.status, 405);
        assert.equal(response.headers.get("Allow"), allow);
        assertProtected(response);
    }
});

test("latency endpoint is minimal, uncached, and rejects query data", async () => {
    const response = await handleRequest(
        new Request(`${ORIGIN}/speed-test/ping/`),
    );
    assert.equal(response.status, 204);
    assert.equal(response.body, null);
    assertProtected(response);

    const withQuery = await handleRequest(
        new Request(`${ORIGIN}/speed-test/ping/?unused=1`),
    );
    assert.equal(withQuery.status, 400);
    assertProtected(withQuery);
});

test("upload streams are counted and discarded without reading a binding", async () => {
    let bindingReads = 0;
    const inaccessibleEnvironment = new Proxy(Object.create(null), {
        get() {
            bindingReads += 1;
            throw new Error("Upload handler must not access external storage");
        },
    });
    const response = await handleRequest(new Request(`${ORIGIN}/speed-test/upload/`, {
        method: "POST",
        headers: {"Content-Type": "application/octet-stream"},
        body: boundedStream(192 * 1024),
        duplex: "half",
    }), inaccessibleEnvironment);

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {received_bytes: 192 * 1024});
    assert.equal(bindingReads, 0);
    assertProtected(response);
});

test("upload Content-Length and actual streamed bytes are independently bounded", async () => {
    assert.equal(MAX_UPLOAD_BYTES, 16 * MIB);
    const declaredTooLarge = await handleRequest(new Request(
        `${ORIGIN}/speed-test/upload/`,
        {
            method: "POST",
            headers: {
                "Content-Length": String(MAX_UPLOAD_BYTES + 1),
                "Content-Type": "application/octet-stream",
            },
            body: new Uint8Array(1),
        },
    ));
    assert.equal(declaredTooLarge.status, 413);
    assertProtected(declaredTooLarge);

    const streamedTooLarge = await handleRequest(new Request(
        `${ORIGIN}/speed-test/upload/`,
        {
            method: "POST",
            headers: {"Content-Type": "application/octet-stream"},
            body: boundedStream(MAX_UPLOAD_BYTES + 1),
            duplex: "half",
        },
    ));
    assert.equal(streamedTooLarge.status, 413);
    assertProtected(streamedTooLarge);
});

test("upload rejects unexpected query parameters and non-binary bodies", async () => {
    const withQuery = await handleRequest(new Request(
        `${ORIGIN}/speed-test/upload/?destination=other`,
        {
            method: "POST",
            headers: {"Content-Type": "application/octet-stream"},
            body: new Uint8Array(16),
        },
    ));
    assert.equal(withQuery.status, 400);
    assertProtected(withQuery);

    const wrongType = await handleRequest(new Request(
        `${ORIGIN}/speed-test/upload/`,
        {
            method: "POST",
            headers: {"Content-Type": "text/plain"},
            body: "not a speed-test payload",
        },
    ));
    assert.equal(wrongType.status, 415);
    assertProtected(wrongType);
});
