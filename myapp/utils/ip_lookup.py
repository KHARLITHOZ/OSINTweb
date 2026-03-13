import ipaddress
import requests

_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting,timezone,query"


def validate_ip(ip: str) -> str:
    """Valida y retorna la IP normalizada, o lanza ValueError."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValueError(f"'{ip}' no es una dirección IP válida.")


def lookup_ip(ip: str) -> dict:
    """
    Consulta ip-api.com y retorna un dict con los datos de la IP.
    Lanza ValueError si la IP es inválida o la API falla.
    """
    ip = validate_ip(ip)

    try:
        resp = requests.get(_API_URL.format(ip=ip), timeout=8)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        raise ValueError(f"Error al contactar ip-api.com: {exc}")

    if data.get("status") != "success":
        raise ValueError(data.get("message", "IP inválida o reservada (ej. IP privada)."))

    return {
        "ip":           data.get("query", ip),
        "country":      data.get("country", ""),
        "country_code": data.get("countryCode", ""),
        "region":       data.get("regionName", ""),
        "city":         data.get("city", ""),
        "latitude":     data.get("lat"),
        "longitude":    data.get("lon"),
        "isp":          data.get("isp", ""),
        "org":          data.get("org", ""),
        "asn":          data.get("as", ""),
        "timezone":     data.get("timezone", ""),
        "is_proxy":     bool(data.get("proxy", False)),
        "is_hosting":   bool(data.get("hosting", False)),
    }
