from django.urls import path
from . import views

urlpatterns = [
    path("",                  views.home,             name="home"),
    path("buscar/ip/",        views.buscar_ip,         name="buscar_ip"),
    path("buscar/dominio/",   views.buscar_dominio,    name="buscar_dominio"),
    path("buscar/email/",     views.buscar_email,      name="buscar_email"),
    path("buscar/comparar/",  views.comparar_dominios, name="comparar_dominios"),
    path("grafo/",            views.grafo,             name="grafo"),
    path("historial/",        views.historial,         name="historial"),
]
