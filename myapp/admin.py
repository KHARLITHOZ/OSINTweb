from django.contrib import admin
from .models import SearchRecord, IPResult, DomainResult, EmailResult


@admin.register(SearchRecord)
class SearchRecordAdmin(admin.ModelAdmin):
    list_display  = ['query', 'query_type', 'success', 'created_at']
    list_filter   = ['query_type', 'success']
    search_fields = ['query']
    ordering      = ['-created_at']
    readonly_fields = ['created_at']


@admin.register(IPResult)
class IPResultAdmin(admin.ModelAdmin):
    list_display  = ['ip', 'city', 'country', 'isp', 'is_proxy', 'is_hosting']
    list_filter   = ['country', 'is_proxy', 'is_hosting']
    search_fields = ['ip', 'isp', 'asn', 'city']
    raw_id_fields = ['record']


@admin.register(DomainResult)
class DomainResultAdmin(admin.ModelAdmin):
    list_display  = ['domain', 'registrar', 'creation_date', 'expiration_date']
    search_fields = ['domain', 'registrar']
    raw_id_fields = ['record']


@admin.register(EmailResult)
class EmailResultAdmin(admin.ModelAdmin):
    list_display  = ['email', 'breach_count']
    search_fields = ['email']
    raw_id_fields = ['record']
