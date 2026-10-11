import os
import socket
from pathlib import Path


def validate_private_key_permissions(file_path: str) -> bool:
    # Verifies that a given private key file has secure permissions (0o400 or 0o600) and is not readable by group/others.
    status = "ERROR"
    key_file = None
    message = "Empty message"
    is_secure = False

    file_mode = 0
    try:
        target = Path(file_path)
        key_file = target.name
        # get file permission as hex
        file_mode = os.stat(target).st_mode
    except FileNotFoundError:
        message = "key_file not found"
        is_secure = False
        print(f"status: {status}, key_file: {file_path}, message: {message}")
        return is_secure

    # cut off information except for the file permission of owner and group, others, masking 9 bits
    parms = file_mode & 0o777

    # check if only owner has read
    if parms == 0o400:
        status = "OK"
        message = "Only owner has read"
        is_secure = True

    # check if only owner has read-write
    elif parms == 0o600:
        status = "OK"
        message = "Only owner has read-write"
        is_secure = True

    # Owner does not have read, or group/others have permissions
    else:
        status = "ERROR"
        message = f"Invalid permissions: {oct(parms)}"
        is_secure = False

    print(f"status: {status}, key_file: {key_file}, message: {message}")
    return is_secure



def audit_security_group_ports(inbound_rules: list) -> dict:
    """
    Evaluates firewall rules and flags any public access (0.0.0.0/0) on management ports 22, 3389, and database ports.
    The scheme refers to Azure Network Security Group
    """

    DANGEROUS_PORTS = [22, 3389, 3306, 5432]
    audit_findings = []

    for rule in inbound_rules:
        port = rule.get("destinationPortRange")
        cidr = rule.get("sourceAddressPrefix")
        action = rule.get("access", "").upper()
    

        if (action == "ALLOW") and (cidr == "0.0.0.0/0" or cidr == "Internet") and (port in DANGEROUS_PORTS):
            audit_findings.append({
                "rule_name" : rule.get("name"),
                "port" : port,
                "severity" : "CRITICAL",
                "message" : f"Port {port} is open to 0.0.0.0/0. Brute force vulnerability"
            })

    return audit_findings



def test_vm_tcp_port(ip_address: str, port: int, timeout: float= 3.0) -> bool:
    # Attempts a TCP connection check to confirm web (Port 80) or SSH (Port 22) availability.

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(("", 80))
    

    # Check if port 80 available

    # Check if port 22 available

    return



if __name__ == "__main__":
    print(validate_private_key_permissions(Path.cwd() / "src" / "lesson77" / "vm_connectivity_auditor.py"))

# Save the execution result into a formatted JSON report: vm_audit_report.json