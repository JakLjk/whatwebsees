from django.urls import path

from .views import (
    browser_check,
    canvas_fingerprint,
    client_ip,
    health,
    home,
    http_headers,
    location,
    network,
    privacy_check,
    request_headers,
    robots_txt,
    screen_resolution,
    sitemap_xml,
    tools,
    user_agent,
    webgl,
)


urlpatterns = [
    path("", home, name="home"),
    path("tools/", tools, name="tools"),
    path("user-agent/", user_agent, name="user-agent"),
    path("browser-check/", browser_check, name="browser-check"),
    path("screen-resolution/", screen_resolution, name="screen-resolution"),
    path("http-headers/", http_headers, name="http-headers"),
    path("privacy-check/", privacy_check, name="privacy-check"),
    path("webgl/", webgl, name="webgl"),
    path(
        "canvas-fingerprint/",
        canvas_fingerprint,
        name="canvas-fingerprint",
    ),
    path("robots.txt", robots_txt, name="robots"),
    path("sitemap.xml", sitemap_xml, name="sitemap"),
    path("health", health, name="health"),
    path("headers", request_headers, name="headers"),
    path("ip", client_ip, name="ip"),
    path("location", location, name="location"),
    path("network", network, name="network"),
]
