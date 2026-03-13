from django.db import models
import json


class SearchRecord(models.Model):
    """Registro central de todas las búsquedas realizadas."""
    TYPE_CHOICES = [
        ('ip', 'IP'),
        ('domain', 'Dominio'),
        ('email', 'Email'),
    ]
    query      = models.CharField(max_length=255)
    query_type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    success    = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.query_type.upper()}] {self.query}"


class IPResult(models.Model):
    record       = models.OneToOneField(SearchRecord, on_delete=models.CASCADE, related_name='ip_result')
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

    def set_list(self, field, data):
        setattr(self, field, json.dumps(data))

    def get_list(self, field):
        val = getattr(self, field)
        return json.loads(val) if val else []

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
