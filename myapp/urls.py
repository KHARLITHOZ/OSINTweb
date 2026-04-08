from django.urls import path
from . import views


urlpatterns = [
    # Auth
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("register/", views.register_view, name="register"),
    # Páginas
    path("", views.home, name="home"),
    path("buscar/ip/", views.buscar_ip, name="buscar_ip"),
    path("buscar/dominio/", views.buscar_dominio, name="buscar_dominio"),
    path("buscar/email/", views.buscar_email, name="buscar_email"),
    path("buscar/comparar/", views.comparar_dominios, name="comparar_dominios"),
    path("grafo/", views.grafo, name="grafo"),
    path("historial/", views.historial, name="historial"),
    path("historial/export/", views.export_historial, name="export_historial"),
    # API interna (proxy IA — requiere login)
    path("api/analyze/", views.api_analyze, name="api_analyze"),
]