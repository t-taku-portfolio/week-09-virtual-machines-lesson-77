import os
import stat
import sys
from pathlib import Path


def validate_private_key_permissions(file_path: str) -> bool:
    # Verifies that a given private key file has secure permissions (0o400 or 0o600) and is not readable by group/others.
    target = Path(file_path)
    if target.exists():
        return {
            "status": "ERROR",
            "message": f"Key file not found at {target}"
            }

    file_mode = os.stat(target).st_mode
    octal_parms = oct(file_mode & 0o777)

    return {"message": "message here"}

def audit_security_group_ports(inbound_rules: list) -> dict:
    # Evaluates firewall rules and flags any public access (0.0.0.0/0) on management ports 22, 3389, and database ports.
    return

def test_vm_tcp_port(ip_address: str, port: int, timeout: float= 3.0) -> bool:
    # Attempts a TCP connection check to confirm web (Port 80) or SSH (Port 22) availability.
    return



# Save the execution result into a formatted JSON report: vm_audit_report.json