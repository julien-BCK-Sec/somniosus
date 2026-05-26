from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Optional, Dict, Any, List

from .runner import run_capture


def _pick_best_address(host_el: ET.Element) -> Optional[str]:
    # Prefer IPv4
    for a in host_el.findall("address"):
        if a.get("addrtype") == "ipv4":
            return a.get("addr")
    # Then IPv6
    for a in host_el.findall("address"):
        if a.get("addrtype") == "ipv6":
            return a.get("addr")
    # Fallback
    a = host_el.find("address")
    return a.get("addr") if a is not None else None


def scan(target: str, outdir: Path) -> Dict[str, Any]:
    """
    Run an nmap scan and return structured results.
    Writes raw nmap.xml into outdir.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    xml_path = outdir / "nmap.xml"

    cmd = ["nmap", "-sV", "-Pn", "-T3", "-oX", str(xml_path), target]
    rc, stdout, stderr = run_capture(cmd)

    # If XML didn't get written, surface the error clearly.
    if not xml_path.exists() or xml_path.stat().st_size == 0:
        raise RuntimeError(
            "nmap output XML missing or empty\n"
            f"rc={rc}\n"
            f"stderr:\n{stderr.strip()}"
        )

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        raise RuntimeError(f"Invalid nmap XML: {e}") from e

    root = tree.getroot()
    hosts: List[Dict[str, Any]] = []

    for host in root.findall("host"):
        status_el = host.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"
        addr = _pick_best_address(host)

        host_obj: Dict[str, Any] = {"address": addr, "status": state, "open_ports": []}

        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                proto = port_el.get("protocol")
                portid = port_el.get("portid")
                service_el = port_el.find("service")

                host_obj["open_ports"].append(
                    {
                        "protocol": proto,
                        "port": int(portid) if portid and portid.isdigit() else portid,
                        "service": service_el.get("name", "") if service_el is not None else "",
                        "product": service_el.get("product", "") if service_el is not None else "",
                        "version": service_el.get("version", "") if service_el is not None else "",
                        "extrainfo": service_el.get("extrainfo", "") if service_el is not None else "",
                    }
                )

        host_obj["open_ports"].sort(key=lambda x: x["port"] if isinstance(x["port"], int) else 999999)
        hosts.append(host_obj)

    flat_ports: List[Dict[str, Any]] = []
    for h in hosts:
        flat_ports.extend(h["open_ports"])

    return {
        "target": target,
        "open_ports": sorted(flat_ports, key=lambda x: x["port"] if isinstance(x["port"], int) else 999999),
        "hosts": hosts,
        # Useful debug info if you ever want it
        "nmap": {"returncode": rc, "stderr": (stderr[:2000] if stderr else ""), "stdout": (stdout[:2000] if stdout else "")},
    }
