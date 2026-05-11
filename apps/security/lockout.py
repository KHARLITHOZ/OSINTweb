"""django-axes lockout callback — returns a proper JSON or HTML response."""
from django.http import JsonResponse
from django.shortcuts import render


def axes_lockout_response(request, credentials, *args, **kwargs):
    if request.headers.get("Accept", "").startswith("application/json"):
        return JsonResponse(
            {"error": "Cuenta bloqueada temporalmente por demasiados intentos fallidos. Intenta en 1 hora."},
            status=403,
        )
    return render(request, "security/lockout.html", status=403)
