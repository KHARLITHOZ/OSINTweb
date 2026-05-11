from django.contrib import admin
from .models import SearchRecord, IPResult, DomainResult, EmailResult


class IPResultInline(admin.StackedInline):
    model = IPResult
    can_delete = False
    extra = 0


class DomainResultInline(admin.StackedInline):
    model = DomainResult
    can_delete = False
    extra = 0


class EmailResultInline(admin.StackedInline):
    model = EmailResult
    can_delete = False
    extra = 0


@admin.register(SearchRecord)
class SearchRecordAdmin(admin.ModelAdmin):
    list_display  = ("id", "user", "query_type", "query", "success", "created_at")
    list_filter   = ("query_type", "success", "created_at")
    search_fields = ("query", "user__username")
    ordering      = ("-created_at",)
    readonly_fields = ("created_at", "ip_address")
    inlines = [IPResultInline, DomainResultInline, EmailResultInline]

    def has_add_permission(self, request):
        return False


@admin.register(IPResult)
class IPResultAdmin(admin.ModelAdmin):
    list_display  = ("ip", "city", "country", "isp", "is_proxy", "is_hosting")
    search_fields = ("ip", "isp", "org")
    list_filter   = ("is_proxy", "is_hosting", "country")


@admin.register(DomainResult)
class DomainResultAdmin(admin.ModelAdmin):
    list_display  = ("domain", "registrar", "creation_date", "expiration_date")
    search_fields = ("domain", "registrar")


@admin.register(EmailResult)
class EmailResultAdmin(admin.ModelAdmin):
    list_display  = ("email", "breach_count")
    search_fields = ("email",)
