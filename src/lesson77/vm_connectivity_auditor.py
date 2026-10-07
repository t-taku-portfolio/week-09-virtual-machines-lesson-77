import os
import stat
import sys
from pathlib import Path


def validate_private_key_permissions(file_path: str) -> bool:
    # Verifies that a given private key file has secure permissions (0o400 or 0o600) and is not readable by group/others.

    try:
        target = Path(file_path)

        # get file permission as hex
        file_mode = os.stat(target).st_mode
    except FileNotFoundError:
        return {
            "status": "ERROR",
            "message": f"Key file not found at {target}"
        }

    # cut off information except for the file permission of owner and group, others, masking 9 bits
    octal_parms = oct(file_mode & 0o777)
    print(octal_parms)

    # check os system and file permission
    if sys.platform == "win32":
        is_secure = not (file_mode & (stat.S_IRGRP | stat.S_IROTH))

    return {
        "message": "sample message",
        "is_secure": is_secure,
        "key_file" : target.name
    }

def audit_security_group_ports(inbound_rules: list) -> dict:
    # Evaluates firewall rules and flags any public access (0.0.0.0/0) on management ports 22, 3389, and database ports.
    return

def test_vm_tcp_port(ip_address: str, port: int, timeout: float= 3.0) -> bool:
    # Attempts a TCP connection check to confirm web (Port 80) or SSH (Port 22) availability.
    return



if __name__ == "__main__":
    print(validate_private_key_permissions("vm_connectivity_auditor.py"))

# Save the execution result into a formatted JSON report: vm_audit_report.json