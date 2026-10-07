import re
from pathlib import Path

class MSFMapper:
    def __init__(self, msf_path="/usr/share/metasploit-framework/modules"):
        self.msf_path = Path(msf_path)
        self.cve_index = None

    def _build_index(self):
        if self.cve_index is not None:
            return self.cve_index

        index = {}
        if not self.msf_path.exists():
            print(f"    [-] MSF modules dir not found: {self.msf_path}")
            self.cve_index = index
            return index

        cve_re = re.compile(
            r"\[\s*'CVE'\s*,\s*'(\d{4}-\d{4,7})'\s*\]",
            re.IGNORECASE
        )

        file_count = 0
        for rb_file in self.msf_path.rglob("*.rb"):
            try:
                text = rb_file.read_text(errors='ignore')
            except OSError:
                continue
            file_count += 1
            module_path = str(rb_file.relative_to(self.msf_path)).replace(".rb", "")
            if module_path.startswith("exploits/"):
                module_path = "exploit/" + module_path[len("exploits/"):]
            for match in cve_re.finditer(text):
                cve = f"CVE-{match.group(1)}"
                index.setdefault(cve, []).append(module_path)

        print(f"    [+] MSF index built: {file_count} files, {len(index)} unique CVEs")
        self.cve_index = index
        return index

    def find_modules(self, cve_id):
        index = self._build_index()
        return index.get(cve_id.upper(), [])

    def map_findings(self, cve_ids):
        self._build_index()
        mapping = {}
        for cve in cve_ids:
            modules = self.find_modules(cve)
            if modules:
                mapping[cve] = modules
        return mapping