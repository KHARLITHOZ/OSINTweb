from django.conf import settings
from django.db import models
import json


class SearchRecord(models.Model):
    """Base central de las búsquedas."""
    TYPE_CHOICES = [
        ('ip', 'IP'),
        ('domain', 'Dominio'),
        ('email', 'Email'),
    ]
    user       = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='searches',
    )
    query      = models.CharField(max_length=255)
    query_type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    success    = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        return f"[{self.query_type.upper()}] {self.query}"


class IPResult(models.Model):
    record       = models.OneToOneField(SearchRecord, on_delete=models.CASCADE, related_name='ip_result') #conexcion con la base central de busquedas
    ip           = models.GenericIPAddressField()
    country      = models.CharField(max_length=100, blank=True)
    country_code = models.CharField(max_length=4, blank=True)
    region       = models.CharField(max_length=100, blank=True)
    city         = models.CharField(max_length=100, blank=True)
    latitude     = models.FloatField(null=True, blank=True)
    longitude    = models.FloatField(null=True, blank=True)
    isp          = models.CharField(max_length=200, blank=True)
    org          = models.CharField(max_length=200, blank=True)
    asn          = models.CharField(max_length=50, blank=True)
    timezone     = models.CharField(max_length=100, blank=True)
    is_proxy     = models.BooleanField(default=False)
    is_hosting   = models.BooleanField(default=False)
    reverse_dns  = models.CharField(max_length=255, blank=True)  # PTR record

    def __str__(self):
        return f"{self.ip} — {self.city}, {self.country}"


class DomainResult(models.Model):
    record          = models.OneToOneField(SearchRecord, on_delete=models.CASCADE, related_name='domain_result')
    domain          = models.CharField(max_length=255)
    registrar       = models.CharField(max_length=255, blank=True)
    creation_date   = models.CharField(max_length=100, blank=True)
    expiration_date = models.CharField(max_length=100, blank=True)
    name_servers    = models.TextField(blank=True)  # JSON list
    dns_a           = models.TextField(blank=True)
    dns_mx          = models.TextField(blank=True)
    dns_ns          = models.TextField(blank=True)
    dns_txt         = models.TextField(blank=True)
    dns_cname       = models.TextField(blank=True)
    subdomains      = models.TextField(blank=True)  # JSON list — crt.sh
    spf_record      = models.CharField(max_length=512, blank=True)
    dmarc_record    = models.CharField(max_length=512, blank=True)

    def set_list(self, field, data):
        setattr(self, field, json.dumps(data))

    def get_list(self, field):
        val = getattr(self, field)
        return json.loads(val) if val else []

    @property
    def name_servers_list(self): return self.get_list('name_servers')

    @property
    def subdomains_list(self): return self.get_list('subdomains')

    @property
    def dns_a_list(self): return self.get_list('dns_a')

    @property
    def dns_mx_list(self): return self.get_list('dns_mx')

    @property
    def dns_ns_list(self): return self.get_list('dns_ns')

    @property
    def dns_txt_list(self): return self.get_list('dns_txt')

    @property
    def dns_cname_list(self): return self.get_list('dns_cname')

    def __str__(self):
        return self.domain


class EmailResult(models.Model):
    record       = models.OneToOneField(SearchRecord, on_delete=models.CASCADE, related_name='email_result')
    email        = models.EmailField()
    breach_count = models.IntegerField(default=0)
    breaches     = models.TextField(blank=True)  # JSON list

    def set_breaches(self, data):
        self.breaches = json.dumps(data)

    def get_breaches(self):
        return json.loads(self.breaches) if self.breaches else []

    def __str__(self):
        return f"{self.email} — {self.breach_count} filtraciones"
