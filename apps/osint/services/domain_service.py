"""Domain OSINT service — wraps the existing lookup logic."""
import json
import re
import requests
import whois
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.core.cache import cache

_CACHE_TTL = 3600 * 6


class DomainService:

    @classmethod
    def lookup(cls, domain: str) -> dict:
        domain = cls._validate(domain)
        cache_key = f"domain:{domain}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        registrar = creation_date = expiration_date = ""
        name_servers: list[str] = []

        try:
            w = whois.whois(domain)
            registrar = w.registrar or ""
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            creation_date = str(cd.date()) if hasattr(cd, "date") else str(cd or "")
            ed = w.expiration_date
            if isinstance(ed, list):
                ed = ed[0]
            expiration_date = str(ed.date()) if hasattr(ed, "date") else str(ed or "")
            ns = w.name_servers
            if ns:
                name_servers = sorted({n.lower().rstrip(".") for n in ns if n})
        except Exception:
            pass

        dns_results: dict[str, list] = {}
        with ThreadPoolExecutor(max_workers=5) as exe:
            futures = {exe.submit(cls._dns_query, domain, t): t for t in ("A", "MX", "NS", "TXT", "CNAME")}
            for fut in as_completed(futures):
                dns_results[futures[fut]] = fut.result()

        txt_records = dns_results.get("TXT", [])
        spf   = next((r for r in txt_records if r.startswith("v=spf1")), "")
        dmarc = next((r for r in cls._dns_query(f"_dmarc.{domain}", "TXT") if r.startswith("v=DMARC1")), "")

        result = {
            "domain":          domain,
            "registrar":       registrar,
            "creation_date":   creation_date,
            "expiration_date": expiration_date,
            "name_servers":    json.dumps(name_servers),
            "dns_a":           json.dumps(dns_results.get("A",     [])),
            "dns_mx":          json.dumps(dns_results.get("MX",    [])),
            "dns_ns":          json.dumps(dns_results.get("NS",    [])),
            "dns_txt":         json.dumps(txt_records),
            "dns_cname":       json.dumps(dns_results.get("CNAME", [])),
            "subdomains":      json.dumps(cls._crt_subdomains(domain)),
            "spf_record":      spf[:512],
            "dmarc_record":    dmarc[:512],
        }
        cache.set(cache_key, result, timeout=_CACHE_TTL)
        return result

    @staticmethod
    def _validate(domain: str) -> str:
        domain = re.sub(r"^https?://", "", domain.strip().lower()).split("/")[0]
        if not re.match(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", domain):
            raise ValueError(f"'{domain}' no es un dominio válido.")
        return domain

    @staticmethod
    def _dns_query(domain: str, rtype: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=8)
            if rtype == "MX":
                return [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
            if rtype == "TXT":
                return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
            return [r.to_text().rstrip(".") for r in answers]
        except Exception:
            return []

    @staticmethod
    def _crt_subdomains(domain: str) -> list[str]:
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=10, headers={"User-Agent": "OSINTng/2.0"},
            )
            if resp.ok:
                subs: set[str] = set()
                for entry in resp.json():
                    for line in entry.get("name_value", "").splitlines():
                        line = line.strip().lstrip("*.")
                        if line and line.endswith(domain) and line != domain:
                            subs.add(line)
                return sorted(subs)[:100]
        except Exception:
            pass
        return []
