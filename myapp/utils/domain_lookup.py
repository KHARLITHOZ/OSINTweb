import re
import json
import requests
import whois
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.core.cache import cache

_CACHE_TTL = 3600 * 6  # 6 horas para dominios


def validate_domain(domain: str) -> str:
    """Valida y normaliza un dominio. Lanza ValueError si no es válido."""
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    pattern = r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    if not re.match(pattern, domain):
        raise ValueError(f"'{domain}' no es un dominio válido.")
    return domain


def _dns_query(domain: str, rtype: str) -> list[str]:
    """Resuelve un tipo de registro DNS. Retorna lista vacía si no existe."""
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=8)
        if rtype == 'MX':
            return [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
        elif rtype == 'TXT':
            return [b''.join(r.strings).decode('utf-8', errors='replace') for r in answers]
        else:
            return [r.to_text().rstrip('.') for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def _get_crt_subdomains(domain: str) -> list[str]:
    """
    Consulta crt.sh (certificate transparency) para obtener subdominios históricos.
    Gratis, sin API key. Retorna lista vacía si falla.
    """
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=10,
            headers={"User-Agent": "OSINTng/1.0"},
        )
        if resp.ok:
            entries = resp.json()
            subdomains = set()
            for entry in entries:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lstrip("*.")
                    if line and line.endswith(domain) and line != domain:
                        subdomains.add(line)
            return sorted(subdomains)[:100]  # máx 100 subdominios
    except Exception:
        pass
    return []


def _extract_spf_dmarc(txt_records: list[str], domain: str) -> tuple[str, str]:
    """Extrae el registro SPF y DMARC de la lista de TXT records."""
    spf = ""
    dmarc = ""

    for record in txt_records:
        if record.startswith("v=spf1") and not spf:
            spf = record

    # DMARC está en _dmarc.<domain>
    dmarc_records = _dns_query(f"_dmarc.{domain}", "TXT")
    for record in dmarc_records:
        if record.startswith("v=DMARC1") and not dmarc:
            dmarc = record

    return spf, dmarc


def lookup_domain(domain: str) -> dict:
    """
    Realiza whois + DNS paralelo + crt.sh para el dominio.
    Cachea resultados 6 horas. Lanza ValueError si el dominio es inválido.
    """
    domain = validate_domain(domain)

    cache_key = f"domain_lookup:{domain}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    # --- WHOIS ---
    registrar = ""
    creation_date = ""
    expiration_date = ""
    name_servers = []

    try:
        w = whois.whois(domain)
        registrar = w.registrar or ""

        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        creation_date = str(cd.date()) if hasattr(cd, 'date') else str(cd or "")

        ed = w.expiration_date
        if isinstance(ed, list):
            ed = ed[0]
        expiration_date = str(ed.date()) if hasattr(ed, 'date') else str(ed or "")

        ns = w.name_servers
        if ns:
            name_servers = sorted({n.lower().rstrip('.') for n in ns if n})
    except Exception:
        pass

    # --- DNS paralelo (A, MX, NS, TXT, CNAME en paralelo) ---
    dns_results = {}
    dns_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(_dns_query, domain, rtype): rtype for rtype in dns_types}
        for future in as_completed(futures):
            rtype = futures[future]
            try:
                dns_results[rtype] = future.result()
            except Exception:
                dns_results[rtype] = []

    dns_a     = dns_results.get('A', [])
    dns_mx    = dns_results.get('MX', [])
    dns_ns    = dns_results.get('NS', [])
    dns_txt   = dns_results.get('TXT', [])
    dns_cname = dns_results.get('CNAME', [])

    # --- SPF / DMARC ---
    spf_record, dmarc_record = _extract_spf_dmarc(dns_txt, domain)

    # --- crt.sh (subdominios) ---
    subdomains = _get_crt_subdomains(domain)

    result = {
        "domain":          domain,
        "registrar":       registrar,
        "creation_date":   creation_date,
        "expiration_date": expiration_date,
        "name_servers":    json.dumps(name_servers),
        "dns_a":           json.dumps(dns_a),
        "dns_mx":          json.dumps(dns_mx),
        "dns_ns":          json.dumps(dns_ns),
        "dns_txt":         json.dumps(dns_txt),
        "dns_cname":       json.dumps(dns_cname),
        "subdomains":      json.dumps(subdomains),
        "spf_record":      spf_record[:512],
        "dmarc_record":    dmarc_record[:512],
    }

    cache.set(cache_key, result, timeout=_CACHE_TTL)
    return result
