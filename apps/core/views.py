"""
Template views — thin controllers.
All OSINT logic lives in apps.osint.services.
All data exposure goes through apps.api (DRF).
These views just render HTML shells; data loads via Axios from the API.
"""
import json
import logging

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST

from apps.osint.services.ip_service     import IPService
from apps.osint.services.domain_service import DomainService
from apps.osint.services.email_service  import EmailService
from .models import SearchRecord, IPResult, DomainResult, EmailResult

logger = logging.getLogger("osint")


@login_required
def home(request):
    stats = {
        "total":   SearchRecord.objects.filter(user=request.user).count(),
        "ip":      SearchRecord.objects.filter(user=request.user, query_type="ip").count(),
        "domain":  SearchRecord.objects.filter(user=request.user, query_type="domain").count(),
        "email":   SearchRecord.objects.filter(user=request.user, query_type="email").count(),
        "recent":  list(
            SearchRecord.objects.filter(user=request.user)
            .values("id", "query", "query_type", "success", "created_at")[:5]
        ),
    }
    return render(request, "pages/home.html", {"stats": stats})


@login_required
def buscar_ip(request):
    result = error = None
    query = ""
    if request.method == "POST":
        query = request.POST.get("ip", "").strip()
        if query:
            try:
                data   = IPService.lookup(query)
                record = SearchRecord.objects.create(
                    user=request.user, query=query, query_type="ip",
                    success=True,
                    ip_address=_requester_ip(request),
                )
                result = IPResult.objects.create(record=record, **data)
            except ValueError as exc:
                error = str(exc)
                SearchRecord.objects.create(
                    user=request.user, query=query, query_type="ip", success=False,
                    ip_address=_requester_ip(request),
                )
        else:
            error = "Introduce una dirección IP."

    return render(request, "pages/ip.html", {
        "result": result,
        "error":  error,
        "query":  query,
    })


@login_required
def buscar_dominio(request):
    result = error = None
    query = ""
    if request.method == "POST":
        query = request.POST.get("dominio", "").strip()
        if query:
            try:
                data   = DomainService.lookup(query)
                record = SearchRecord.objects.create(
                    user=request.user, query=data["domain"], query_type="domain",
                    success=True, ip_address=_requester_ip(request),
                )
                result = DomainResult.objects.create(record=record, **data)
            except ValueError as exc:
                error = str(exc)
                SearchRecord.objects.create(
                    user=request.user, query=query, query_type="domain", success=False,
                    ip_address=_requester_ip(request),
                )
        else:
            error = "Introduce un dominio."

    return render(request, "pages/domain.html", {
        "result": result,
        "error":  error,
        "query":  query,
    })


@login_required
def buscar_email(request):
    result = analysis = error = None
    query = ""
    if request.method == "POST":
        query = request.POST.get("email", "").strip()
        if query:
            try:
                data = EmailService.lookup(query)
            except ValueError as exc:
                error = str(exc)
                data  = None
            except Exception:
                error = "Error al analizar el email. Inténtalo de nuevo."
                logger.exception("email lookup failed for %s", query)
                data = None

            if data is not None:
                try:
                    record   = SearchRecord.objects.create(
                        user=request.user, query=data["email"], query_type="email",
                        success=True, ip_address=_requester_ip(request),
                    )
                    result   = EmailResult.objects.create(record=record, **data)
                    analysis = result.get_breaches()
                except Exception:
                    error = "Error al guardar el resultado."
                    logger.exception("email DB write failed for %s", query)

            SearchRecord.objects.filter(
                user=request.user, query=query, query_type="email", success=False
            ).exists() or (error and SearchRecord.objects.create(
                user=request.user, query=query, query_type="email", success=False,
                ip_address=_requester_ip(request),
            ))
        else:
            error = "Introduce un correo electrónico."

    return render(request, "pages/email.html", {
        "result":   result,
        "analysis": analysis,
        "error":    error,
        "query":    query,
    })


@login_required
def grafo(request):
    nodes, link_set, links = {}, set(), []

    def add_node(nid, label, ntype, info=""):
        nodes.setdefault(nid, {"id": nid, "label": label, "type": ntype, "info": info})

    def add_link(src, tgt, label):
        key = (src, tgt, label)
        if key not in link_set:
            link_set.add(key)
            links.append({"source": src, "target": tgt, "label": label})

    qs_filter = dict(record__success=True, record__user=request.user)

    for ip in IPResult.objects.select_related("record").filter(**qs_filter)[:200]:
        ip_id = f"ip:{ip.ip}"
        add_node(ip_id, ip.ip, "ip", f"{ip.city}, {ip.country}")
        if ip.isp:
            isp_id = f"isp:{ip.isp}"; add_node(isp_id, ip.isp, "isp"); add_link(ip_id, isp_id, "ISP")
        if ip.asn:
            asn_id = f"asn:{ip.asn}"; add_node(asn_id, ip.asn, "asn"); add_link(ip_id, asn_id, "ASN")

    for dom in DomainResult.objects.select_related("record").filter(**qs_filter)[:200]:
        dom_id = f"domain:{dom.domain}"
        add_node(dom_id, dom.domain, "domain", dom.registrar or "")
        for a in dom.dns_a_list:
            ip_id = f"ip:{a}"; add_node(ip_id, a, "ip"); add_link(dom_id, ip_id, "A")
        for ns in dom.dns_ns_list:
            ns_id = f"ns:{ns.rstrip('.')}"; add_node(ns_id, ns.rstrip("."), "ns"); add_link(dom_id, ns_id, "NS")
        for mx in dom.dns_mx_list:
            parts = mx.split(" ", 1); host = (parts[1] if len(parts) == 2 else mx).rstrip(".")
            mx_id = f"mx:{host}"; add_node(mx_id, host, "mx"); add_link(dom_id, mx_id, "MX")

    for em in EmailResult.objects.select_related("record").filter(**qs_filter)[:200]:
        em_id = f"email:{em.email}"; add_node(em_id, em.email, "email")
        analysis = em.get_breaches()
        if analysis.get("domain"):
            d_id = f"domain:{analysis['domain']}"
            add_node(d_id, analysis["domain"], "domain"); add_link(em_id, d_id, "dominio")

    return render(request, "pages/graph.html", {
        "graph":     {"nodes": list(nodes.values()), "links": links},
        "has_graph": bool(nodes),
    })


@login_required
def historial(request):
    tipo = request.GET.get("tipo", "")
    qs   = SearchRecord.objects.filter(user=request.user)
    if tipo in ("ip", "domain", "email"):
        qs = qs.filter(query_type=tipo)

    return render(request, "pages/history.html", {
        "tipo_activo": tipo,
        "total":       qs.count(),
    })


@login_required
def comparar_dominios(request):
    def _lookup(q):
        if not q:
            return None, None
        try:
            data   = DomainService.lookup(q)
            record = SearchRecord.objects.create(
                user=request.user, query=data["domain"], query_type="domain",
                success=True, ip_address=_requester_ip(request),
            )
            return DomainResult.objects.create(record=record, **data), None
        except ValueError as exc:
            SearchRecord.objects.create(
                user=request.user, query=q, query_type="domain", success=False,
                ip_address=_requester_ip(request),
            )
            return None, str(exc)

    q1, q2     = request.GET.get("d1", "").strip(), request.GET.get("d2", "").strip()
    r1, err1   = _lookup(q1)
    r2, err2   = _lookup(q2)

    return render(request, "pages/compare.html", {
        "result1": r1, "error1": err1, "q1": q1,
        "result2": r2, "error2": err2, "q2": q2,
    })


# ── Helpers ───────────────────────────────────────────────────────────────────

def _requester_ip(request) -> str | None:
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR")
