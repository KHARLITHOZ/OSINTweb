"""
DRF API views — all data I/O goes through here.
Frontend talks exclusively to these endpoints via Axios.
"""
import csv
import logging

from django.http import HttpResponse
from rest_framework import status
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.models import SearchRecord, IPResult, DomainResult, EmailResult
from apps.osint.services.ip_service     import IPService
from apps.osint.services.domain_service import DomainService
from apps.osint.services.email_service  import EmailService
from apps.osint.services.ai_service     import AIService

from .serializers import (
    SearchRecordSerializer,
    IPResultSerializer,
    DomainResultSerializer,
    EmailResultSerializer,
    IPLookupInputSerializer,
    DomainLookupInputSerializer,
    EmailLookupInputSerializer,
    AIAnalysisInputSerializer,
    HistorialQuerySerializer,
)
from .throttles import OSINTThrottle, AIThrottle, ExportThrottle
from .pagination import StandardPagination

logger = logging.getLogger("osint")


# ── IP ────────────────────────────────────────────────────────────────────────

class IPLookupView(APIView):
    throttle_classes = [OSINTThrottle]

    def post(self, request):
        inp = IPLookupInputSerializer(data=request.data)
        if not inp.is_valid():
            return Response({"error": inp.errors}, status=status.HTTP_400_BAD_REQUEST)

        ip = inp.validated_data["ip"]
        try:
            data = IPService.lookup(ip)
        except ValueError as exc:
            SearchRecord.objects.create(
                user=request.user, query=ip, query_type="ip",
                success=False, ip_address=_req_ip(request),
            )
            return Response({"error": str(exc)}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        record = SearchRecord.objects.create(
            user=request.user, query=ip, query_type="ip",
            success=True, ip_address=_req_ip(request),
        )
        result = IPResult.objects.create(record=record, **data)
        return Response(IPResultSerializer(result).data, status=status.HTTP_201_CREATED)


# ── Domain ────────────────────────────────────────────────────────────────────

class DomainLookupView(APIView):
    throttle_classes = [OSINTThrottle]

    def post(self, request):
        inp = DomainLookupInputSerializer(data=request.data)
        if not inp.is_valid():
            return Response({"error": inp.errors}, status=status.HTTP_400_BAD_REQUEST)

        domain = inp.validated_data["domain"]
        try:
            data = DomainService.lookup(domain)
        except ValueError as exc:
            SearchRecord.objects.create(
                user=request.user, query=domain, query_type="domain",
                success=False, ip_address=_req_ip(request),
            )
            return Response({"error": str(exc)}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        record = SearchRecord.objects.create(
            user=request.user, query=data["domain"], query_type="domain",
            success=True, ip_address=_req_ip(request),
        )
        result = DomainResult.objects.create(record=record, **data)
        return Response(DomainResultSerializer(result).data, status=status.HTTP_201_CREATED)


# ── Email ─────────────────────────────────────────────────────────────────────

class EmailLookupView(APIView):
    throttle_classes = [OSINTThrottle]

    def post(self, request):
        inp = EmailLookupInputSerializer(data=request.data)
        if not inp.is_valid():
            return Response({"error": inp.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = inp.validated_data["email"]
        try:
            data = EmailService.lookup(email)
        except ValueError as exc:
            SearchRecord.objects.create(
                user=request.user, query=email, query_type="email",
                success=False, ip_address=_req_ip(request),
            )
            return Response({"error": str(exc)}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        except Exception:
            logger.exception("email lookup API failed for %s", email)
            return Response({"error": "Error al consultar el email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        record = SearchRecord.objects.create(
            user=request.user, query=data["email"], query_type="email",
            success=True, ip_address=_req_ip(request),
        )
        result = EmailResult.objects.create(record=record, **data)
        return Response(EmailResultSerializer(result).data, status=status.HTTP_201_CREATED)


# ── AI Analysis ───────────────────────────────────────────────────────────────

class AIAnalysisView(APIView):
    throttle_classes = [AIThrottle]

    def post(self, request):
        inp = AIAnalysisInputSerializer(data=request.data)
        if not inp.is_valid():
            return Response({"error": inp.errors}, status=status.HTTP_400_BAD_REQUEST)

        try:
            analysis = AIService.analyze(
                inp.validated_data["type"],
                inp.validated_data["data"],
            )
            return Response({"analysis": analysis})
        except ValueError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)


# ── History ───────────────────────────────────────────────────────────────────

class HistorialView(APIView):

    def get(self, request):
        qs_params = HistorialQuerySerializer(data=request.query_params)
        if not qs_params.is_valid():
            return Response({"error": qs_params.errors}, status=status.HTTP_400_BAD_REQUEST)

        tipo = qs_params.validated_data["tipo"]
        qs   = SearchRecord.objects.filter(user=request.user)
        if tipo:
            qs = qs.filter(query_type=tipo)

        paginator = StandardPagination()
        page      = paginator.paginate_queryset(qs, request)
        serializer = SearchRecordSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


# ── Graph data ────────────────────────────────────────────────────────────────

class GraphDataView(APIView):

    def get(self, request):
        nodes, link_set, links = {}, set(), []

        def add_node(nid, label, ntype, info=""):
            nodes.setdefault(nid, {"id": nid, "label": label, "type": ntype, "info": info})

        def add_link(src, tgt, label):
            key = (src, tgt, label)
            if key not in link_set:
                link_set.add(key)
                links.append({"source": src, "target": tgt, "label": label})

        f = dict(record__success=True, record__user=request.user)

        for ip in IPResult.objects.select_related("record").filter(**f)[:200]:
            nid = f"ip:{ip.ip}"
            add_node(nid, ip.ip, "ip", f"{ip.city}, {ip.country}")
            if ip.isp:
                iid = f"isp:{ip.isp}"; add_node(iid, ip.isp, "isp"); add_link(nid, iid, "ISP")
            if ip.asn:
                aid = f"asn:{ip.asn}"; add_node(aid, ip.asn, "asn"); add_link(nid, aid, "ASN")

        for dom in DomainResult.objects.select_related("record").filter(**f)[:200]:
            did = f"domain:{dom.domain}"
            add_node(did, dom.domain, "domain", dom.registrar or "")
            for a in dom.dns_a_list:
                iid = f"ip:{a}"; add_node(iid, a, "ip"); add_link(did, iid, "A")
            for ns in dom.dns_ns_list:
                nid = f"ns:{ns.rstrip('.')}"; add_node(nid, ns.rstrip("."), "ns"); add_link(did, nid, "NS")

        for em in EmailResult.objects.select_related("record").filter(**f)[:200]:
            eid = f"email:{em.email}"; add_node(eid, em.email, "email")
            analysis = em.get_breaches()
            if analysis.get("domain"):
                did = f"domain:{analysis['domain']}"
                add_node(did, analysis["domain"], "domain"); add_link(eid, did, "dominio")

        return Response({"nodes": list(nodes.values()), "links": links})


# ── Export ────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@throttle_classes([ExportThrottle])
def export_csv(request):
    tipo = request.query_params.get("tipo", "")
    qs   = SearchRecord.objects.filter(user=request.user)
    if tipo in ("ip", "domain", "email"):
        qs = qs.filter(query_type=tipo)

    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="osint_historial.csv"'
    writer = csv.writer(response)
    writer.writerow(["ID", "Tipo", "Consulta", "Fecha", "Estado"])
    for rec in qs:
        writer.writerow([
            rec.id, rec.query_type, rec.query,
            rec.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "OK" if rec.success else "Error",
        ])
    return response


# ── Stats (dashboard) ─────────────────────────────────────────────────────────

@api_view(["GET"])
def stats(request):
    qs = SearchRecord.objects.filter(user=request.user)
    return Response({
        "total":  qs.count(),
        "ip":     qs.filter(query_type="ip").count(),
        "domain": qs.filter(query_type="domain").count(),
        "email":  qs.filter(query_type="email").count(),
        "recent": SearchRecordSerializer(qs[:5], many=True).data,
    })


# ── Helpers ───────────────────────────────────────────────────────────────────

def _req_ip(request) -> str | None:
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR")
