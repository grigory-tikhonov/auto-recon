import os
import re
import time
import requests
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

GENERIC_WORDS = {
    "http", "server", "service", "daemon", "engine", "linux", "gnu",
    "db", "database", "shell", "root",
    "netkit", "classpath", "bindshell", "metasploitable",
}

VENDOR_WORDS = {
    "microsoft", "apache", "oracle", "google", "ibm", "cisco",
    "juniper", "sun", "red", "hat", "canonical", "debian", "ubuntu",
}

SYNONYM_RULES = [
    (r'\bhttpd\b', ['http server', 'apache http']),
    (r'\bsmbd\b', ['smb']),
    (r'\bsmtpd\b', ['smtp']),
    (r'\brexecd\b', ['rexec']),
    (r'\brshd\b', ['rsh']),
]

DISTRO_PATTERN = re.compile(
    r'[- ]?(debian|ubuntu|deb\d*|ubuntu\d*|el\d*|centos|rhel|fedora|suse|arch|gentoo)[-\w.]*$',
    re.IGNORECASE
)

class NVDChecker:
    def __init__(self):
        self.api_key = os.getenv("NVD_API_KEY")
        if not self.api_key:
            print("[!] ATTENTION: The NVD_API_KEY is not set.")
            print("    The limit will be reduced to 5 requests per 30 seconds.")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.delay = 0.7 if self.api_key else 7.0
        self.last_request_time = None
        self.cache = {}

    def _rate_limit(self):
        if self.last_request_time:
            elapsed = (datetime.now() - self.last_request_time).total_seconds()
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
        self.last_request_time = datetime.now()

    def _clean_version(self, version):
        if isinstance(version, list):
            version = " ".join(str(v) for v in version)
        version = str(version).strip()
        if " - " in version:
            version = version.split(" - ")[0].strip()
        version = re.split(r'\s+(debian|ubuntu)', version, flags=re.IGNORECASE)[0].strip()
        version = DISTRO_PATTERN.sub("", version)
        return version.strip()

    def _expand_keywords(self, keywords):
        expanded = set(k.lower() for k in keywords)
        for kw in keywords:
            for pattern, synonyms in SYNONYM_RULES:
                if re.search(pattern, kw.lower()):
                    expanded.update(s.lower() for s in synonyms)
        return list(expanded)

    def _extract_keywords(self, product):
        tokens = re.findall(r'[A-Za-z][A-Za-z0-9]+', product)
        keywords = [t for t in tokens if t.lower() not in GENERIC_WORDS]
        keywords.sort(key=lambda w: (
            w.lower() in VENDOR_WORDS,
            -len(w)
        ))
        return keywords
    
    def _version_in_desc(self, version, desc):
        if not version:
            return False
        pattern = r'(?<![\d.])' + re.escape(version) + r'(?![\d.])'
        return bool(re.search(pattern, desc, re.IGNORECASE))

    def _major_minor_in_desc(self, major_minor, desc):
        if not major_minor:
            return False
        pattern = r'(?<![\d.])' + re.escape(major_minor) + r'(?!\d)'
        return bool(re.search(pattern, desc, re.IGNORECASE))

    def _version_tuple(self, v):
        parts = re.findall(r'\d+', str(v))
        return tuple(int(p) for p in parts[:4]) if parts else (0,)

    def _is_affected_by_range(self, our_version, description):
        if not our_version:
            return None
        our = self._version_tuple(our_version)
        desc = description.lower()

        m = re.search(r'(?:before|prior to|earlier than)\s+(\d+\.\d+(?:\.\d+)?)', desc)
        if m:
            return our < self._version_tuple(m.group(1))

        m = re.search(r'(\d+\.\d+(?:\.\d+)?)\s+and\s+(?:earlier|before)', desc)
        if m:
            return our <= self._version_tuple(m.group(1))

        m = re.search(r'(\d+\.\d+(?:\.\d+)?)\s+(?:through|to)\s+(\d+\.\d+(?:\.\d+)?)', desc)
        if m:
            low = self._version_tuple(m.group(1))
            high = self._version_tuple(m.group(2))
            return low <= our <= high

        m = re.search(r'(\d+\.\d+(?:\.\d+)?)\s+and\s+(\d+\.\d+(?:\.\d+)?)', desc)
        if m:
            v1 = self._version_tuple(m.group(1))
            v2 = self._version_tuple(m.group(2))
            return our == v1 or our == v2

        m = re.search(r'through\s+(\d+\.\d+(?:\.\d+)?)', desc)
        if m:
            return our <= self._version_tuple(m.group(1))

        return None

    def _extract_major_minor(self, version):
        m = re.match(r'(\d+)\.(\d+)', version)
        return f"{m.group(1)}.{m.group(2)}" if m else None

    def _query_nvd(self, query):
        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {"keywordSearch": query, "resultsPerPage": 100}
        self._rate_limit()
        try:
            r = requests.get(self.base_url, headers=headers, params=params, timeout=30)
        except requests.RequestException as e:
            print(f"    [-] Error in the request to the NVD: {e}")
            return []
        if r.status_code != 200:
            return []
        results = []
        for item in r.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                ""
            )
            metrics = cve.get("metrics", {})
            score, severity = "N/A", "N/A"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metrics.get(key):
                    cvss = metrics[key][0].get("cvssData", {})
                    score = cvss.get("baseScore", "N/A")
                    severity = cvss.get("baseSeverity", "N/A")
                    break
            results.append({
                "cve_id": cve.get("id", "N/A"),
                "description": desc,
                "score": score,
                "severity": severity,
            })
        return results

    def _filter_cves(self, cves, keywords, version):
        if not keywords:
            return []
        expanded = self._expand_keywords(keywords)
        specific = [k for k in expanded if k.lower() not in VENDOR_WORDS]
        if not specific:
            specific = [k.lower() for k in expanded]
        
        major_minor = self._extract_major_minor(version) if version else None

        filtered = []
        for c in cves:
            desc = c["description"].lower()

            if not any(k in desc for k in specific):
                continue

            if version:
                if self._version_in_desc(version, desc):
                    confidence = "HIGH"
                elif major_minor and self._major_minor_in_desc(major_minor, desc):
                    confidence = "MEDIUM"
                else:
                    continue
            else:
                confidence = "LOW"

            rng = self._is_affected_by_range(version, c["description"])
            if rng is False:
                continue

            c["confidence"] = confidence
            filtered.append(c)

        return filtered

    def search_cve(self, product, version):
        product = str(product).strip() if product else ""
        version_clean = self._clean_version(version) if version else ""
        cache_key = f"{product}::{version_clean}".lower()
        if cache_key in self.cache:
            return self.cache[cache_key]

        keywords = self._extract_keywords(product)
        if not keywords:
            self.cache[cache_key] = []
            return []

        queries = []
        if version_clean:
            for kw in keywords[:2]:
                queries.append(f"{kw} {version_clean}")
        for kw in keywords[:2]:
            queries.append(kw)

        seen_q = set()
        unique_queries = []
        for q in queries:
            if q.lower() not in seen_q:
                seen_q.add(q.lower())
                unique_queries.append(q)

        merged = []
        seen_cve = set()
        for q in unique_queries:
            raw = self._query_nvd(q)
            filtered = self._filter_cves(raw, keywords, version_clean)
            for c in filtered:
                if c["cve_id"] not in seen_cve:
                    seen_cve.add(c["cve_id"])
                    merged.append(c)

        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        merged.sort(key=lambda c: (
            order.get(c.get("confidence", "LOW"), 3),
            -float(c["score"]) if c["score"] not in ("N/A", None) else 0
        ))

        self.cache[cache_key] = merged
        return merged

    def check_services(self, scan_results):
        print("\n[*] Checking services via the NVD API...")
        enriched = []
        for service in scan_results:
            product = str(service.get("product", "")).strip()
            version = service.get("version", "")
            if not product or product.lower() in ["unknown", ""]:
                continue

            banner = f"{product} {version}".strip()
            print(f"    [>] Checking: {banner} (port {service['port']})")

            cves = self.search_cve(product, version)
            service_copy = dict(service)
            service_copy["cves"] = cves
            enriched.append(service_copy)

            if cves:
                for c in cves[:5]:
                    conf = c.get("confidence", "LOW")
                    desc = c["description"]
                    product_lower = product.lower()
                    version_lower = version.lower() if version else ""
                    idx = desc.lower().find(product_lower)
                    if idx == -1:
                        idx = desc.lower().find(version_lower) if version_lower else -1
                    if idx > 20:
                        snippet = "..." + desc[idx-20:idx+80]
                    else:
                        snippet = desc[:90]
                    print(f"    [{conf}] {c['cve_id']} (CVSS {c['score']}): {snippet}...")
            else:
                print(f"    [+] CVE not found in the NVD.")
        return enriched
                
