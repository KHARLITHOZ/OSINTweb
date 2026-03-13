from django.shortcuts import render

from .models import SearchRecord, IPResult
from .utils.ip_lookup import lookup_ip


def home(request):
    return render(request, 'myapp/home.html')


def buscar_ip(request):
    result = None
    error = None
    query = ""

    if request.method == "POST":
        query = request.POST.get("ip", "").strip()
        if not query:
            error = "Introduce una dirección IP."
        else:
            try:
                data = lookup_ip(query)
                record = SearchRecord.objects.create(
                    query=query,
                    query_type="ip",
                    success=True,
                )
                result = IPResult.objects.create(record=record, **data)
            except ValueError as exc:
                error = str(exc)
                SearchRecord.objects.create(
                    query=query,
                    query_type="ip",
                    success=False,
                )

    return render(request, "myapp/ip.html", {
        "result": result,
        "error": error,
        "query": query,
    })


def buscar_dominio(request):
    return render(request, 'myapp/base.html')


def buscar_email(request):
    return render(request, 'myapp/base.html')


def grafo(request):
    return render(request, 'myapp/base.html')


def historial(request):
    return render(request, 'myapp/base.html')
