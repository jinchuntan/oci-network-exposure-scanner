import oci

SUSPICIOUS_PORTS = {22: "SSH", 3389: "RDP", 80: "HTTP", 443: "HTTPS"}


def _is_world_cidr(cidr: str) -> bool:
    return cidr == "0.0.0.0/0"


def _port_in_range(port: int, min_p: int, max_p: int) -> bool:
    return min_p <= port <= max_p


def _extract_tcp_ports(tcp_options):
    # tcp_options has destination_port_range (min/max) usually
    if not tcp_options or not getattr(tcp_options, "destination_port_range", None):
        return None
    pr = tcp_options.destination_port_range
    return int(pr.min), int(pr.max)


def scan_security_lists(vcn_client, compartment_id: str):
    results = []
    slists = vcn_client.list_security_lists(compartment_id=compartment_id).data
    for sl in slists:
        for rule in sl.ingress_security_rules:
            if rule.protocol != "6":  # TCP
                continue
            if not _is_world_cidr(rule.source):
                continue

            ports = _extract_tcp_ports(rule.tcp_options)
            if not ports:
                # No port range = could be all ports (more severe)
                results.append({
                    "resource_type": "security_list",
                    "resource_name": sl.display_name,
                    "resource_ocid": sl.id,
                    "rule_type": "ingress",
                    "source": rule.source,
                    "protocol": "TCP",
                    "ports": "ALL",
                    "risk": "HIGH",
                    "note": "Ingress from 0.0.0.0/0 with no TCP destination port range specified.",
                })
                continue

            pmin, pmax = ports
            hit_ports = []
            for p, label in SUSPICIOUS_PORTS.items():
                if _port_in_range(p, pmin, pmax):
                    hit_ports.append(f"{label}({p})")

            if hit_ports:
                results.append({
                    "resource_type": "security_list",
                    "resource_name": sl.display_name,
                    "resource_ocid": sl.id,
                    "rule_type": "ingress",
                    "source": rule.source,
                    "protocol": "TCP",
                    "ports": f"{pmin}-{pmax}",
                    "risk": "MEDIUM",
                    "note": f"Ingress from 0.0.0.0/0 on {', '.join(hit_ports)}.",
                })
    return results


def scan_nsgs(vcn_client, compartment_id: str):
    results = []
    nsgs = vcn_client.list_network_security_groups(compartment_id=compartment_id).data
    for nsg in nsgs:
        rules = vcn_client.list_network_security_group_security_rules(
            network_security_group_id=nsg.id
        ).data
        for rule in rules:
            if rule.direction != "INGRESS":
                continue
            if rule.protocol != "6":  # TCP
                continue
            if not _is_world_cidr(rule.source):
                continue

            ports = _extract_tcp_ports(rule.tcp_options)
            if not ports:
                results.append({
                    "resource_type": "nsg",
                    "resource_name": nsg.display_name,
                    "resource_ocid": nsg.id,
                    "rule_type": "ingress",
                    "source": rule.source,
                    "protocol": "TCP",
                    "ports": "ALL",
                    "risk": "HIGH",
                    "note": "NSG ingress from 0.0.0.0/0 with no TCP destination port range specified.",
                })
                continue

            pmin, pmax = ports
            hit_ports = []
            for p, label in SUSPICIOUS_PORTS.items():
                if _port_in_range(p, pmin, pmax):
                    hit_ports.append(f"{label}({p})")

            if hit_ports:
                results.append({
                    "resource_type": "nsg",
                    "resource_name": nsg.display_name,
                    "resource_ocid": nsg.id,
                    "rule_type": "ingress",
                    "source": rule.source,
                    "protocol": "TCP",
                    "ports": f"{pmin}-{pmax}",
                    "risk": "MEDIUM",
                    "note": f"NSG ingress from 0.0.0.0/0 on {', '.join(hit_ports)}.",
                })
    return results
