import json
from django.conf import settings
from django.db import models
from django.utils import timezone


class SearchRecord(models.Model):
    TYPE_IP     = "ip"
    TYPE_DOMAIN = "domain"
    TYPE_EMAIL  = "email"
    TYPE_CHOICES = [
        (TYPE_IP,     "IP"),
        (TYPE_DOMAIN, "Dominio"),
        (TYPE_EMAIL,  "Email"),
    ]

    user       = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name="searches",
    )
    query      = models.CharField(max_length=255, db_index=True)
    query_type = models.CharField(max_length=10, choices=TYPE_CHOICES, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    success    = models.BooleanField(default=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)   # requester IP for audit

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "-created_at"]),
            models.Index(fields=["query_type", "-created_at"]),
            models.Index(fields=["-created_at"]),
        ]

    def __str__(self):
        return f"[{self.query_type.upper()}] {self.query}"


class IPResult(models.Model):
    record       = models.OneToOneField(SearchRecord, on_delete=models.CASCADE, related_name="ip_result")
    ip           = models.GenericIPAddressField()
    country      = models.CharField(max_length=100, blank=True)
    country_code = models.CharField(max_length=4,   blank=True)
    region       = models.CharField(max_length=100, blank=True)
    city         = models.CharField(max_length=100, blank=True)
    latitude     = models.FloatField(null=True, blank=True)
    longitude    = models.FloatField(null=True, blank=True)
    isp          = models.CharField(max_length=200, blank=True)
    org          = models.CharField(max_length=200, blank=True)
    asn          = models.CharField(max_length=50,  blank=True)
    timezone     = models.CharField(max_length=100, blank=True)
    is_proxy     = models.BooleanField(default=False)
    is_hosting   = models.BooleanField(default=False)
    reverse_dns  = models.CharField(max_length=255, blank=True)

    class Meta:
        indexes = [models.Index(fields=["ip"])]

    def __str__(self):
        return f"{self.ip} — {self.city}, {self.country}"

    @property
    def risk_level(self) -> str:
        if self.is_proxy or self.is_hosting:
            return "high"
        return "low"


class DomainResult(models.Model):
    record          = models.OneToOneField(SearchRecord, on_delete=models.CASCADE, related_name="domain_result")
    domain          = models.CharField(max_length=255, db_index=True)
    registrar       = models.CharField(max_length=255, blank=True)
    creation_date   = models.CharField(max_length=100, blank=True)
    expiration_date = models.CharField(max_length=100, blank=True)
    name_servers    = models.TextField(blank=True)   # JSON list
    dns_a           = models.TextField(blank=True)
    dns_mx          = models.TextField(blank=True)
    dns_ns          = models.TextField(blank=True)
    dns_txt         = models.TextField(blank=True)
    dns_cname       = models.TextField(blank=True)
    subdomains      = models.TextField(blank=True)
    spf_record      = models.CharField(max_length=512, blank=True)
    dmarc_record    = models.CharField(max_length=512, blank=True)

    def _get(self, field: str) -> list:
        val = getattr(self, field)
        if not val:
            return []
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return []

    def _set(self, field: str, data: list) -> None:
        setattr(self, field, json.dumps(data))

    # Convenience properties
    @property
    def name_servers_list(self): return self._get("name_servers")
    @property
    def subdomains_list(self):   return self._get("subdomains")
    @property
    def dns_a_list(self):        return self._get("dns_a")
    @property
    def dns_mx_list(self):       return self._get("dns_mx")
    @property
    def dns_ns_list(self):       return self._get("dns_ns")
    @property
    def dns_txt_list(self):      return self._get("dns_txt")
    @property
    def dns_cname_list(self):    return self._get("dns_cname")

    # Keep backward-compat alias used in views
    def get_list(self, field: str) -> list:
        return self._get(field)

    def __str__(self):
        return self.domain


class EmailResult(models.Model):
    record       = models.OneToOneField(SearchRecord, on_delete=models.CASCADE, related_name="email_result")
    email        = models.EmailField(db_index=True)
    breach_count = models.IntegerField(default=0)
    breaches     = models.TextField(blank=True)    # JSON

    def get_breaches(self) -> dict:
        if not self.breaches:
            return {}
        try:
            return json.loads(self.breaches)
        except (json.JSONDecodeError, TypeError):
            return {}

    def __str__(self):
        return f"{self.email} — {self.breach_count} filtraciones"
