from django.urls import path

from .views import (
    client_ip,
    health,
    home,
    location,
    network,
    request_headers,
    robots_txt,
    sitemap_xml,
)


urlpatterns = [
    path("", home, name="home"),
    path("robots.txt", robots_txt, name="robots"),
    path("sitemap.xml", sitemap_xml, name="sitemap"),
    path("health", health, name="health"),
    path("headers", request_headers, name="headers"),
    path("ip", client_ip, name="ip"),
    path("location", location, name="location"),
    path("network", network, name="network"),
]
