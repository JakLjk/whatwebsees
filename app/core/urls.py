from django.urls import path

from .views import client_ip, health, home, request_headers


urlpatterns = [
    path("", home, name="home"),
    path("health", health, name="health"),
    path("headers", request_headers, name="headers"),
    path("ip", client_ip, name="ip"),
]
