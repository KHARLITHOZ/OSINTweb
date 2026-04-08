import json
import logging

from django.shortcuts import render, redirect
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.utils.http import url_has_allowed_host_and_scheme
import csv

logger = logging.getLogger('osint')

from .models import SearchRecord, IPResult, DomainResult, EmailResult
from .utils.ip_lookup import lookup_ip
from .utils.domain_lookup import lookup_domain
from .utils.email_lookup import lookup_email


# ──────────────────────────────────────────────
# Auth
# ──────────────────────────────────────────────

def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    error = None
    username = ""

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, f"Bienvenido de nuevo, {user.username}.")
            next_url = request.GET.get('next', '/')
            if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
                next_url = '/'
            return redirect(next_url)
        error = "Usuario o contraseña incorrectos."

    return render(request, "myapp/login.html", {"error": error, "username": username})


@require_POST
def logout_view(request):
    logout(request)
    return redirect('login')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    errors = []
    form_data = {}

    if request.method == "POST":
        username  = request.POST.get("username", "").strip()
        email     = request.POST.get("email", "").strip()
        password1 = request.POST.get("password1", "")
        password2 = request.POST.get("password2", "")
        form_data = {"username": username, "email": email}

        if not username:
            errors.append("El nombre de usuario es obligatorio.")
        elif User.objects.filter(username=username).exists():
            errors.append("Ese nombre de usuario ya está en uso.")

        if password1 != password2:
            errors.append("Las contraseñas no coinciden.")
        else:
            try:
                validate_password(password1)
            except ValidationError as e:
                errors.extend(e.messages)

        if not errors:
            user = User.objects.create_user(username=username, email=email, password=password1)
            login(request, user)
            messages.success(request, f"Cuenta creada. Bienvenido, {user.username}.")
            return redirect('home')

    return render(request, "myapp/register.html", {"errors": errors, "form_data": form_data})


# ──────────────────────────────────────────────
# Páginas principales
# ──────────────────────────────────────────────

@login_required
def home(request):
    return render(request, 'myapp/home.html')


# ──────────────────────────────────────────────
# Herramientas OSINT
# ──────────────────────────────────────────────

@login_required
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
                    user=request.user,
                    query=query,
                    query_type="ip",
                    success=True,
                )
                result = IPResult.objects.create(record=record, **data)
            except ValueError as exc:
                error = str(exc)
                SearchRecord.objects.create(
                    user=request.user,
                    query=query,
                    query_type="ip",
                    success=False,
                )

    ip_data = {
        "ip": result.ip,
        "country": result.country or "",
        "country_code": result.country_code or "",
        "region": result.region or "",
        "city": result.city or "",
        "latitude": result.latitude,
        "longitude": result.longitude,
        "isp": result.isp or "",
        "org": result.org or "",
        "asn": result.asn or "",
        "timezone": result.timezone or "",
        "is_proxy": result.is_proxy,
        "is_hosting": result.is_hosting,
    } if result else None
    return render(request, "myapp/ip.html", {
        "result": result,
        "ip_data": ip_data,
        "error": error,
        "query": query,
    })


@login_required
def buscar_dominio(request):
    result = None
    error = None
    query = ""

    if request.method == "POST":
        query = request.POST.get("dominio", "").strip()
        if not query:
            error = "Introduce un dominio."
        else:
            try:
                data = lookup_domain(query)
                record = SearchRecord.objects.create(
                    user=request.user,
                    query=data["domain"],
                    query_type="domain",
                    success=True,
                )
                result = DomainResult.objects.create(record=record, **data)
            except ValueError as exc:
                error = str(exc)
                SearchRecord.objects.create(
                    user=request.user,
                    query=query,
                    query_type="domain",
                    success=False,
                )

    result_data = {
        "domain":          result.domain,
        "registrar":       result.registrar or "",
        "creation_date":   result.creation_date or "",
        "expiration_date": result.expiration_date or "",
        "name_servers":    result.get_list("name_servers"),
        "dns_a":           result.get_list("dns_a"),
        "dns_mx":          result.get_list("dns_mx"),
        "dns_ns":          result.get_list("dns_ns"),
        "dns_txt":         result.get_list("dns_txt"),
        "dns_cname":       result.get_list("dns_cname"),
    } if result else None

    return render(request, "myapp/dominio.html", {
        "result": result,
        "result_data": result_data,
        "error": error,
        "query": query,
    })


@login_required
def buscar_email(request):
    result = None
    analysis = None
    error = None
    query = ""

    if request.method == "POST":
        query = request.POST.get("email", "").strip()
        if not query:
            error = "Introduce un correo electrónico."
        else:
            # Fase 1: lookup externo (DNS, HIBP) — FUERA de cualquier transacción DB
            data = None
            try:
                data = lookup_email(query)
            except ValueError as exc:
                error = str(exc)
                logger.warning("buscar_email formato inválido para %s: %s", query, exc)
            except Exception:
                error = "Error al analizar el email. Inténtalo de nuevo."
                logger.exception("buscar_email lookup falló para %s", query)

            # Fase 2: persistencia en DB — solo si el lookup fue exitoso
            if data is not None:
                try:
                    record = SearchRecord.objects.create(
                        user=request.user,
                        query=data["email"],
                        query_type="email",
                        success=True,
                    )
                    result = EmailResult.objects.create(record=record, **data)
                    analysis = json.loads(result.breaches)
                except Exception:
                    error = "Error al guardar el resultado. Inténtalo de nuevo."
                    logger.exception("buscar_email DB write falló para %s", query)
            elif not error:
                # lookup retornó None sin excepción — no debería ocurrir
                error = "No se pudo obtener información del email."

    email_data = {"email": result.email, **analysis} if result and analysis else None
    return render(request, "myapp/email.html", {
        "result": result,
        "analysis": analysis,
        "email_data": email_data,
        "error": error,
        "query": query,
    })


@login_required
def grafo(request):
    nodes = {}   # id -> {id, label, type, info}
    link_set = set()  # (source, target, label) para deduplicar
    links = []

    def add_node(nid, label, ntype, info=""):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "type": ntype, "info": info}

    def add_link(source, target, label):
        key = (source, target, label)
        if key not in link_set:
            link_set.add(key)
            links.append({"source": source, "target": target, "label": label})

    # ── IPs ──────────────────────────────────────
    for ip in IPResult.objects.select_related('record').filter(
            record__success=True, record__user=request.user)[:200]:
        ip_id = f"ip:{ip.ip}"
        add_node(ip_id, ip.ip, "ip", f"{ip.city}, {ip.country}")

        if ip.isp:
            isp_id = f"isp:{ip.isp}"
            add_node(isp_id, ip.isp, "isp")
            add_link(ip_id, isp_id, "ISP")

        if ip.asn:
            asn_id = f"asn:{ip.asn}"
            add_node(asn_id, ip.asn, "asn")
            add_link(ip_id, asn_id, "ASN")

    # ── Dominios ─────────────────────────────────
    for dom in DomainResult.objects.select_related('record').filter(
            record__success=True, record__user=request.user)[:200]:
        dom_id = f"domain:{dom.domain}"
        add_node(dom_id, dom.domain, "domain", dom.registrar or "")

        # A records → IPs
        for ip_addr in dom.get_list("dns_a"):
            ip_id = f"ip:{ip_addr}"
            add_node(ip_id, ip_addr, "ip")
            add_link(dom_id, ip_id, "A")

        # NS records
        for ns in dom.get_list("dns_ns"):
            ns_clean = ns.rstrip(".")
            ns_id = f"ns:{ns_clean}"
            add_node(ns_id, ns_clean, "ns")
            add_link(dom_id, ns_id, "NS")

        # MX records (extraer solo hostname, sin prioridad)
        for mx in dom.get_list("dns_mx"):
            parts = mx.split(" ", 1)
            mx_host = parts[1].rstrip(".") if len(parts) == 2 else mx.rstrip(".")
            mx_id = f"mx:{mx_host}"
            add_node(mx_id, mx_host, "mx")
            add_link(dom_id, mx_id, "MX")

    # ── Emails ───────────────────────────────────
    for em in EmailResult.objects.select_related('record').filter(
            record__success=True, record__user=request.user)[:200]:
        email_id = f"email:{em.email}"
        add_node(email_id, em.email, "email")

        if em.breaches:
            analysis = json.loads(em.breaches)
            domain = analysis.get("domain", "")
            if domain:
                dom_id = f"domain:{domain}"
                add_node(dom_id, domain, "domain")
                add_link(email_id, dom_id, "dominio")

                # Si el dominio tiene MX, conectar email → MX
                for mx in analysis.get("mx_records", []):
                    parts = mx.split(" ", 1)
                    mx_host = parts[1].rstrip(".") if len(parts) == 2 else mx.rstrip(".")
                    mx_id = f"mx:{mx_host}"
                    add_node(mx_id, mx_host, "mx")
                    add_link(dom_id, mx_id, "MX")

    graph = {
        "nodes": list(nodes.values()),
        "links": links,
    }

    return render(request, 'myapp/grafo.html', {
        "graph": graph,
        "has_graph": bool(nodes),
    })


@login_required
@require_POST
def api_analyze(request):
    """Proxy seguro hacia Claude API — la API key nunca sale del servidor."""
    try:
        body = json.loads(request.body)
        query_type = body.get("type", "")
        data = body.get("data", {})
        if not query_type or not isinstance(data, dict):
            return JsonResponse({"error": "Petición inválida."}, status=400)
    except (json.JSONDecodeError, Exception):
        return JsonResponse({"error": "JSON inválido."}, status=400)

    try:
        from .utils.ai_analysis import analyze_with_claude
        analysis = analyze_with_claude(query_type, data)
        return JsonResponse({"analysis": analysis})
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)


@login_required
def comparar_dominios(request):
    """Comparación lado a lado de dos dominios."""
    result1 = result2 = None
    error1 = error2 = None
    q1 = request.GET.get("d1", "").strip()
    q2 = request.GET.get("d2", "").strip()

    if q1:
        try:
            data = lookup_domain(q1)
            record = SearchRecord.objects.create(user=request.user, query=data["domain"], query_type="domain", success=True)
            result1 = DomainResult.objects.create(record=record, **data)
        except ValueError as exc:
            error1 = str(exc)
            SearchRecord.objects.create(user=request.user, query=q1, query_type="domain", success=False)

    if q2:
        try:
            data = lookup_domain(q2)
            record = SearchRecord.objects.create(user=request.user, query=data["domain"], query_type="domain", success=True)
            result2 = DomainResult.objects.create(record=record, **data)
        except ValueError as exc:
            error2 = str(exc)
            SearchRecord.objects.create(user=request.user, query=q2, query_type="domain", success=False)

    def _domain_dict(r):
        if not r:
            return None
        return {
            "domain": r.domain,
            "registrar": r.registrar or "",
            "creation_date": r.creation_date or "",
            "expiration_date": r.expiration_date or "",
            "dns_a": r.dns_a_list,
            "dns_ns": r.dns_ns_list,
            "dns_mx": r.dns_mx_list,
            "dns_txt": r.dns_txt_list,
        }

    return render(request, "myapp/comparar.html", {
        "result1": result1, "error1": error1, "q1": q1,
        "result2": result2, "error2": error2, "q2": q2,
        "data1": _domain_dict(result1),
        "data2": _domain_dict(result2),
    })


@login_required
def export_historial(request):
    """Exporta el historial del usuario como CSV."""
    qs = SearchRecord.objects.filter(user=request.user).order_by('-created_at')
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="osint_historial.csv"'
    writer = csv.writer(response)
    writer.writerow(['ID', 'Tipo', 'Consulta', 'Fecha', 'Estado'])
    for rec in qs:
        writer.writerow([
            rec.id,
            rec.query_type,
            rec.query,
            rec.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'OK' if rec.success else 'Error',
        ])
    return response


@login_required
def historial(request):
    tipo = request.GET.get('tipo', '')
    qs = SearchRecord.objects.filter(user=request.user)
    if tipo in ('ip', 'domain', 'email'):
        qs = qs.filter(query_type=tipo)

    paginator = Paginator(qs, 20)
    page_num = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_num)

    return render(request, 'myapp/historial.html', {
        'page_obj': page_obj,
        'tipo_activo': tipo,
        'total': paginator.count,
    })
