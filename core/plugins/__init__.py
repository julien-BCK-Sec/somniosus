# core/plugins/__init__.py
from __future__ import annotations

from core.registry import Registry

from core.plugins.nmap import NmapTool
from core.plugins.httpx import HttpxMainTool, HttpxSubdomainsTool
from core.plugins.subfinder import SubfinderTool
from core.plugins.crtsh import CrtshTool
from core.plugins.dnssec import DnssecTool
from core.plugins.dns_enum import DnsEnumTool
from core.plugins.dnstwist import DnstwistTool
from core.plugins.tldx import TldxTool
from core.plugins.whois import WhoisTool
from core.plugins.whois_tldx import WhoisTldxTool
from core.plugins.ssl_enum import SslEnumTool
from core.plugins.katana import KatanaTool
from core.plugins.httpx_katana import HttpxKatanaTool
from core.plugins.nuclei import NucleiTool
from core.plugins.ffuf import FfufTool



def build_registry() -> Registry:
    reg = Registry()
    reg.register(NmapTool())
    reg.register(HttpxMainTool())
    reg.register(CrtshTool())
    reg.register(SubfinderTool())
    reg.register(HttpxSubdomainsTool())
    reg.register(KatanaTool())
    reg.register(HttpxKatanaTool())
    reg.register(DnssecTool())
    reg.register(DnsEnumTool())
    reg.register(DnstwistTool())
    reg.register(TldxTool())
    reg.register(WhoisTool())
    reg.register(WhoisTldxTool())
    reg.register(SslEnumTool())
    reg.register(NucleiTool())
    reg.register(FfufTool())
    return reg
