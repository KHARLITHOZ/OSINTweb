from rest_framework import serializers
from apps.core.models import SearchRecord, IPResult, DomainResult, EmailResult


class SearchRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model  = SearchRecord
        fields = ("id", "query", "query_type", "success", "created_at")
        read_only_fields = fields


class IPResultSerializer(serializers.ModelSerializer):
    class Meta:
        model  = IPResult
        fields = (
            "ip", "country", "country_code", "region", "city",
            "latitude", "longitude", "isp", "org", "asn",
            "timezone", "is_proxy", "is_hosting", "reverse_dns", "risk_level",
        )
        read_only_fields = fields


class DomainResultSerializer(serializers.ModelSerializer):
    name_servers_list = serializers.ListField(child=serializers.CharField(), read_only=True)
    dns_a_list        = serializers.ListField(child=serializers.CharField(), read_only=True)
    dns_mx_list       = serializers.ListField(child=serializers.CharField(), read_only=True)
    dns_ns_list       = serializers.ListField(child=serializers.CharField(), read_only=True)
    dns_txt_list      = serializers.ListField(child=serializers.CharField(), read_only=True)
    dns_cname_list    = serializers.ListField(child=serializers.CharField(), read_only=True)
    subdomains_list   = serializers.ListField(child=serializers.CharField(), read_only=True)

    class Meta:
        model  = DomainResult
        fields = (
            "domain", "registrar", "creation_date", "expiration_date",
            "spf_record", "dmarc_record",
            "name_servers_list", "dns_a_list", "dns_mx_list",
            "dns_ns_list", "dns_txt_list", "dns_cname_list", "subdomains_list",
        )
        read_only_fields = fields


class EmailResultSerializer(serializers.ModelSerializer):
    analysis = serializers.SerializerMethodField()

    class Meta:
        model  = EmailResult
        fields = ("email", "breach_count", "analysis")
        read_only_fields = fields

    def get_analysis(self, obj):
        return obj.get_breaches()


# ── Input serializers (validated request bodies) ──────────────────────────────

class IPLookupInputSerializer(serializers.Serializer):
    ip = serializers.IPAddressField()


class DomainLookupInputSerializer(serializers.Serializer):
    domain = serializers.CharField(max_length=253, min_length=3)

    def validate_domain(self, value):
        import re
        value = value.strip().lower().lstrip("http://").lstrip("https://").split("/")[0]
        if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$", value):
            raise serializers.ValidationError("Dominio inválido.")
        return value


class EmailLookupInputSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)

    def validate_email(self, value):
        return value.strip().lower()


class AIAnalysisInputSerializer(serializers.Serializer):
    SUPPORTED = {"ip", "domain", "email"}
    type = serializers.ChoiceField(choices=list(SUPPORTED))
    data = serializers.DictField(child=serializers.CharField(max_length=300))

    def validate_data(self, value):
        if len(value) > 20:
            raise serializers.ValidationError("Demasiados campos en data.")
        return value


class HistorialQuerySerializer(serializers.Serializer):
    tipo = serializers.ChoiceField(choices=["", "ip", "domain", "email"], required=False, default="")
    page = serializers.IntegerField(min_value=1, required=False, default=1)
