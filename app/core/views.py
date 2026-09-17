from ipaddress import ip_address

from django.http import JsonResponse
from django.shortcuts import render
from django.utils.cache import patch_cache_control
from django.views.decorators.http import require_GET, require_safe


@require_safe
def home(request):
    return render(request, "core/home.html")


@require_GET
def health(request):
    return JsonResponse({"status": "ok"})


def private_json_response(data, *, status=200):
    response = JsonResponse(data, status=status)
    patch_cache_control(response, private=True, no_store=True)
    return response


@require_GET
def client_ip(request):
    value = request.META.get("HTTP_X_REAL_IP")

    try:
        address = ip_address(value.strip())
    except (AttributeError, ValueError):
        return private_json_response(
            {"error": "client_ip_unavailable"}, status=503
        )

    return private_json_response(
        {
            "ip": str(address),
            "version": address.version,
            "is_public": address.is_global,
        }
    )
