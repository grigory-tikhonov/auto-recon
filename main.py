import argparse
import sys
from modules.scanner import NetworkScanner
from modules.exploits import VulnerabilityChecker
from modules.vuln_checker import NVDChecker
from modules.msf_mapper import MSFMapper
from modules.report import ReportGenerator

def parse_args():
    parser = argparse.ArgumentParser(
        prog="auto-recon",
        description="Passive vulnerability scanner: Nmap + NVD + Metasploit correlation.",
        epilog="Example: sudo python3 main.py 192.168.56.103 --summary-only",
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print only the summary, exploits, and auxiliary blocks "
             "(skip the verbose NVD listing). Useful for CI pipelines.",
    )
    parser.add_argument(
        "--no-reports",
        action="store_true",
        help="Skip report generation (JSON/HTML files).",
    )
    return parser.parse_args()

def categorize_msf(modules):
    exploits = []
    auxiliary = []
    for m in modules:
        if m.startswith("exploit/"):
            exploits.append(m)
        elif m.startswith("auxiliary/"):
            auxiliary.append(m)
        else:
            auxiliary.append(m)
    return exploits, auxiliary

def main():
    args = parse_args()
    target = args.target

    # Port scan
    scanner = NetworkScanner(target)
    scan_results = scanner.scan()
    if not scan_results:
        print("[-] The scan had no results. Exit.")
        sys.exit(1)

    # Built-in signature DB
    checker = VulnerabilityChecker()
    findings = checker.check(scan_results)
    
    # NVD lookup
    nvd = NVDChecker()
    enriched = nvd.check_services(scan_results)
    
    # Collect all CVE IDs
    all_cve_ids = set()
    for f in findings:
        if f.get("cve") and f["cve"] != "N/A":
            all_cve_ids.add(f["cve"])
    for s in enriched:
        for c in s.get("cves", []):
            if c.get("confidence") in ("HIGH", "MEDIUM"):
                all_cve_ids.add(c["cve_id"])
    
    # Map CVEs to Metasploit modules  
    print("\n[*] Mapping CVEs to Metasploit modules...")
    mapper = MSFMapper()
    msf_map = mapper.map_findings(sorted(all_cve_ids))

    # Save reports
    if not args.no_reports:
        reporter = ReportGenerator(target)
        json_path, html_path = reporter.generate(scan_results, findings, enriched, msf_map)
        print(f"\n[*] Reports saved:")
        print(f"    JSON: {json_path}")
        print(f"    HTML: {html_path}")
    
    # Final report
    total_nvd = sum(
        len([c for c in s.get("cves", []) if c.get("confidence") in ("HIGH", "MEDIUM")])
        for s in enriched
    )

    print("\n" + "=" * 70)
    print(f"[*] SCAN SUMMARY for {target}")
    print("=" * 70)
    print(f"    Open ports:                 {len(scan_results)}")
    print(f"    Built-in DB findings:       {len(findings)}")
    print(f"    NVD findings (HIGH/MEDIUM): {total_nvd}")
    print(f"    Exploitable (with MSF):     {len(msf_map)}")
    print("=" * 70)

    # Built-in DB section
    print("\n[*] VULNERABILITIES (built-in signature DB)")
    print("-" * 70)
    if findings:
        for f in findings:
            print(f"    [!] Port {f['port']:>5}/{f['service']:<12} {f['banner'] if 'banner' in f else ''}")
            print(f"        CVE: {f['cve']}")
            print(f"        {f['description']}")
    else:
        print("     [*] No known vulnerabilities found.")

    # NVD section (skippable)
    if not args.summary_only:
        print("\n[*] VULNERABILITIES (NVD API, HIGH/MEDIUM confidence)")
        print("-" * 70)
        printed_any = False
        for s in enriched:
            cves = [c for c in s.get("cves", []) if c.get("confidence") in ("HIGH", "MEDIUM")]
            if not cves:
                continue
            printed_any = True
            print(f"    Port {s['port']}/{s['service']} ({s['product']} {s['version']}):")
            for c in cves:
                sev = c.get("severity", "N/A")
                print(f"        [{c['confidence']:<6}] {c['cve_id']:<15} CVSS {c['score']:<4} {sev}")
        if not printed_any:
            print("     [+] No high-confidence findings.")
    else:
        print(f"\n[*] ({total_nvd} NVD findings hidden - run without --summary-only to see them)")

    # MSF modules section
    print("\n[*] EXPLOITABLE (Metasploit modules mapped)")
    print("-" * 70)
    
    exploits_map, auxiliary_map = {}, {}
    for cve, modules in msf_map.items():
        exps, aux = categorize_msf(modules)
        if exps:
            exploits_map[cve] = exps
        if aux:
            auxiliary_map[cve] = aux
    
    if exploits_map:
        for cve, modules in sorted(exploits_map.items()):
            print(f"    {cve}")
            for m in modules:
                print(f"        -> {m}")
    else:
        print("     [-] No runnable exploits found.")

    if auxiliary_map:
        print("\n[*] AUXILIARY / VERIFICATION (non-exploit modules)")
        print("-" * 70)
        for cve, modules in sorted(auxiliary_map.items()):
            print(f"    {cve}")
            for m in modules:
                print(f"        -> {m}")

    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()