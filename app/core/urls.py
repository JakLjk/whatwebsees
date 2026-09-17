from django.urls import path

from .views import client_ip, health


urlpatterns = [
    path("health", health, name="health"),
    path("ip", client_ip, name="ip"),
]
