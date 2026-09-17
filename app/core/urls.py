from django.urls import path

from .views import client_ip, health, home


urlpatterns = [
    path("", home, name="home"),
    path("health", health, name="health"),
    path("ip", client_ip, name="ip"),
]
