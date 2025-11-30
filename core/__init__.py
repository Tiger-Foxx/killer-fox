"""
FoxProwl Core Module
"""
from .config import conf, attack_conf, NetworkConfig, AttackConfig
from .logger import log, console
from .network import NetworkDiscovery
from .mitigation import SystemControl
from .utils import (
    resolve_domain,
    domain_matches,
    is_valid_ip,
    expand_cidr,
    Counter,
    RateLimiter
)

__all__ = [
    'conf',
    'attack_conf',
    'NetworkConfig',
    'AttackConfig',
    'log',
    'console',
    'NetworkDiscovery',
    'SystemControl',
    'resolve_domain',
    'domain_matches',
    'is_valid_ip',
    'expand_cidr',
    'Counter',
    'RateLimiter'
]
