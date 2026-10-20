import os
import socket
from pathlib import Path


def is_port_in_dangerous(port_range: any, dangerous_ports: list) -> bool:
    """
    Audit the port range, and check if they are included in dangerous ports.
    Port range is expressed as integer or range. For example, 22 or "8000-8080".
    """

    # check if it specifies all ports
    if port_range == "*":
        return True
    # check if it is single port as int
    elif isinstance(port_range, int):
        return port_range in dangerous_ports
    # check if it is ports as range. i.e, "20-22" as a str
    elif isinstance(port_range, str):
        if "-" in port_range:
            port_list = port_range.split("-")
            # combination with chained comparison and generator expression, any function
            return any(int(port_list[0]) <= the_dangerous_port <= int(port_list[1]) for the_dangerous_port in dangerous_ports)
        else:
            return int(port_range) in dangerous_ports
        
    return False



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



def audit_security_group_ports(inbound_rules: list) -> list:
    """
    Evaluates firewall rules and flags any public access (0.0.0.0/0) on management ports 22, 3389, and database ports. Inbound traffic from 0.0.0.0/0 to administrative ports should be denied. The scheme refers to Azure Network Security Group
    """


    DANGEROUS_PORTS = [22, 3389, 3306, 5432]
    audit_findings = []

    for rule in inbound_rules:
        is_port_a_list = None
        properties_dict = rule.get("properties", {})

        # if the parameter has single port range
        if "destinationPortRange" in properties_dict:
            port = properties_dict.get("destinationPortRange")
            is_port_a_list = False

        # if the parameter has a list of port range
        elif "destinationPortRanges" in properties_dict:
            port = properties_dict.get("destinationPortRanges")
            is_port_a_list = True

        else:
            audit_findings.append({
                "rule_name" : rule.get("name"),
                "message" : "The rule does not have port setting"
            })

        cidr = properties_dict.get("sourceAddressPrefix")
        action = properties_dict.get("access", "").upper()
    
        if is_port_a_list:
            for the_port in port:
                involve_dangerous_port = is_port_in_dangerous(port_range=the_port, dangerous_ports=DANGEROUS_PORTS)

                if (action == "ALLOW") and (cidr == "0.0.0.0/0" or cidr == "Internet") and involve_dangerous_port:
                    audit_findings.append({
                        "rule_name" : rule.get("name"),
                        "port" : the_port,
                        "severity" : "CRITICAL",
                        "message" : f"Port {port} is open to 0.0.0.0/0. Brute force vulnerability"
                    })
        else:
            involve_dangerous_port = is_port_in_dangerous(port_range=port, dangerous_ports=DANGEROUS_PORTS)

            if (action == "ALLOW") and (cidr == "0.0.0.0/0" or cidr == "Internet") and involve_dangerous_port:
                audit_findings.append({
                    "rule_name" : rule.get("name"),
                    "port" : port,
                    "severity" : "CRITICAL",
                    "message" : f"Port {port} is open to 0.0.0.0/0. Brute force vulnerability"
                })

    return audit_findings



def test_vm_tcp_port(ip_address: str, port: int, timeout: float= 3.0) -> bool:
    # Attempts a TCP connection check to confirm like web (Port 80) and SSH (Port 22) availability.

    with socket.create_connection((ip_address, port), timeout):
        try:
            return True
        except (ConnectionRefusedError, OSError):
            return False



if __name__ == "__main__":
    print(validate_private_key_permissions(Path.cwd() / "src" / "lesson77" / "vm_connectivity_auditor.py"))
    print(f'is port20 available: {test_vm_tcp_port(ip_address= "127.0.0.1", port= 20)}')
    print(f'is port80 available: {test_vm_tcp_port(ip_address= "127.0.0.1", port= 80)}')

# Save the execution result into a formatted JSON report: vm_audit_report.json
