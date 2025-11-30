"""
FoxProwl Attack Modules
"""
from .scanner import NetworkScanner, scan_network
from .arp_spoof import ARPSpoofer
from .dns_spoof import DNSSpoofer
from .tcp_killer import TCPKiller
from .internet_control import InternetBlocker, block_internet
from .session_hijack import SessionHijacker
from .ssl_strip import SSLStripper
from .http_injector import HTTPInjector

__all__ = [
    'NetworkScanner',
    'scan_network',
    'ARPSpoofer',
    'DNSSpoofer',
    'TCPKiller',
    'InternetBlocker',
    'block_internet',
    'SessionHijacker',
    'SSLStripper',
    'HTTPInjector'
]
