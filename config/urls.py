from django.contrib import admin
from django.urls import path, include
from django.conf import settings

urlpatterns = [
    path("admin/",  admin.site.urls),
    path("auth/",   include("allauth.urls")),
    path("api/v1/", include("apps.api.urls", namespace="api")),
    path("",        include("apps.core.urls")),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns = [path("__debug__/", include(debug_toolbar.urls))] + urlpatterns
