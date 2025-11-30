""" Configuration globale et état du moteur """
from dataclasses import dataclass
from typing import Optional

@dataclass
class Config:
    interface: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    local_ip: Optional[str] = None
    local_mac: Optional[str] = None
    network_cidr: Optional[str] = None
    monitor_mode: bool = False

config = Config()
