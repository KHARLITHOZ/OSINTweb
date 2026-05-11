from django.urls import path
from . import views

app_name = "api"

urlpatterns = [
    # OSINT lookups
    path("lookup/ip/",     views.IPLookupView.as_view(),     name="lookup_ip"),
    path("lookup/domain/", views.DomainLookupView.as_view(), name="lookup_domain"),
    path("lookup/email/",  views.EmailLookupView.as_view(),  name="lookup_email"),

    # AI proxy
    path("analyze/",       views.AIAnalysisView.as_view(),   name="analyze"),

    # History & graph
    path("history/",       views.HistorialView.as_view(),    name="history"),
    path("graph/",         views.GraphDataView.as_view(),    name="graph"),

    # Stats
    path("stats/",         views.stats,                      name="stats"),

    # Exports
    path("export/csv/",    views.export_csv,                 name="export_csv"),
]
