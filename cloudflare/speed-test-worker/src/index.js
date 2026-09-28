const MIB = 1024 * 1024;

export const BACKEND = "cloudflare-worker";
export const MAX_UPLOAD_BYTES = 16 * MIB;

const COMMON_HEADERS = Object.freeze({
    "Cache-Control": "no-store, no-cache, no-transform",
    "X-Robots-Tag": "noindex, nofollow",
    "X-WWS-Speedtest-Backend": BACKEND,
    "X-Content-Type-Options": "nosniff",
});

function response(body = null, init = {}) {
    const headers = new Headers(COMMON_HEADERS);
    for (const [name, value] of new Headers(init.headers)) {
        headers.set(name, value);
    }
    return new Response(body, {...init, headers});
}

function jsonError(status, error, extraHeaders = {}) {
    return response(JSON.stringify({error}), {
        status,
        headers: {
            "Content-Type": "application/json; charset=utf-8",
            ...extraHeaders,
        },
    });
}

function hasNoQueryParameters(url) {
    return [...url.searchParams].length === 0;
}

function parseContentLength(request) {
    const value = request.headers.get("Content-Length");
    if (value === null) return null;
    if (!/^\d+$/.test(value)) return Number.NaN;
    return Number(value);
}

async function handleUpload(request) {
    const contentType = request.headers.get("Content-Type")?.split(";", 1)[0].trim();
    if (contentType !== "application/octet-stream") {
        return jsonError(415, "unsupported_media_type");
    }
    const contentLength = parseContentLength(request);
    if (
        Number.isNaN(contentLength)
        || contentLength > MAX_UPLOAD_BYTES
    ) {
        return jsonError(413, "upload_too_large");
    }
    if (!request.body) return jsonError(400, "upload_body_required");

    const reader = request.body.getReader();
    let receivedBytes = 0;
    try {
        while (true) {
            const {done, value} = await reader.read();
            if (done) break;
            receivedBytes += value.byteLength;
            if (receivedBytes > MAX_UPLOAD_BYTES) {
                await reader.cancel("upload exceeds speed-test limit");
                return jsonError(413, "upload_too_large");
            }
        }
    } finally {
        reader.releaseLock();
    }

    if (contentLength !== null && receivedBytes !== contentLength) {
        return jsonError(400, "incomplete_upload");
    }

    return response(JSON.stringify({received_bytes: receivedBytes}), {
        status: 200,
        headers: {"Content-Type": "application/json; charset=utf-8"},
    });
}

export async function handleRequest(request) {
    const url = new URL(request.url);

    if (url.pathname === "/speed-test/ping/") {
        if (request.method !== "GET") {
            return jsonError(405, "method_not_allowed", {Allow: "GET"});
        }
        if (!hasNoQueryParameters(url)) return jsonError(400, "unexpected_query");
        return response(null, {status: 204});
    }

    if (url.pathname === "/speed-test/upload/") {
        if (request.method !== "POST") {
            return jsonError(405, "method_not_allowed", {Allow: "POST"});
        }
        if (!hasNoQueryParameters(url)) return jsonError(400, "unexpected_query");
        return handleUpload(request);
    }

    return jsonError(404, "not_found");
}

export default {
    fetch(request) {
        return handleRequest(request);
    },
};
