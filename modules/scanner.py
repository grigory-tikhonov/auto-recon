import nmap
import sys

class NetworkScanner:
    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()

    def scan(self):
        print(f"[*] Starting to scan the target: {self.target}")

        try:
            self.scanner.scan(hosts=self.target, arguments='-sV -sC -T4')
        except Exception as e:
            print(f"[-] Scan error: {e}")
            return None

        results = []
        
        for host in self.scanner.all_hosts():
            print(f"[+] Host: {host} ({self.scanner[host].hostname()})")
            print(f"    State: {self.scanner[host].state()}")

            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()
                
                for port in sorted(ports):
                    state = self.scanner[host][proto][port]['state']
                    name = self.scanner[host][proto][port]['name']
                    product = self.scanner[host][proto][port]['product']
                    version = self.scanner[host][proto][port]['version']

                    service_info = {
                        'port': port,
                        'protocol': proto,
                        'state': state,
                        'service': name,
                        'product': product,
                        'version': version
                    }
                    results.append(service_info)
                    print(f"    Port {port}/{proto}: {state} | {name} {product} {version}")
        
        return results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Using: python3 scanner.py <IP address>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    scanner = NetworkScanner(target_ip)
    scanner.scan()
